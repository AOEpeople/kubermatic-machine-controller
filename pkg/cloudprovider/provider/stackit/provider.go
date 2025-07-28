/*
Copyright 2019 The Machine Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package stackit

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
	cloudprovidererrors "k8c.io/machine-controller/pkg/cloudprovider/errors"
	"k8c.io/machine-controller/pkg/cloudprovider/instance"
	cloudprovidertypes "k8c.io/machine-controller/pkg/cloudprovider/types"
	clusterv1alpha1 "k8c.io/machine-controller/sdk/apis/cluster/v1alpha1"
	stackittypes "k8c.io/machine-controller/sdk/cloudprovider/stackit"
	"k8c.io/machine-controller/sdk/providerconfig"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/stackitcloud/stackit-sdk-go/core/config"
	"github.com/stackitcloud/stackit-sdk-go/core/utils"
	"github.com/stackitcloud/stackit-sdk-go/services/iaas"
	"github.com/stackitcloud/stackit-sdk-go/services/iaas/wait"
)

const (
	serverStatusActive   = "ACTIVE"
	serverStatusCreating = "CREATING"
	serverStatusDeleted  = "DELETED"
	serverStatusDeleting = "DELETING"

	labelKeyMachineUID = "machine-uid"
)

type provider struct {
	configVarResolver providerconfig.ConfigVarResolver
}

// New returns a stackit provider.
func New(configVarResolver providerconfig.ConfigVarResolver) cloudprovidertypes.Provider {
	return &provider{configVarResolver: configVarResolver}
}

type Config struct {
	Token               string
	ProjectID           string
	MachineType         string
	AvailabilityZone    string
	BootVolumeSize      int64
	BootVolumeImageId   string
	Labels              map[string]interface{}
	Network             string
	SecurityGroups      []string
	KeypairName         string
	AffinityGroup       string
	ServiceAccountMails []string
	Volumes             []string
}

type stackitInstance struct {
	server *iaas.Server
}

func (i *stackitInstance) Name() string {
	return i.server.GetName()
}

func (i *stackitInstance) ID() string {
	return i.server.GetId()
}

func (i *stackitInstance) ProviderID() string {
	id := i.ID()
	if id == "" {
		return ""
	}
	return fmt.Sprintf("stackit://%s", id)
}

func (i *stackitInstance) Addresses() map[string]corev1.NodeAddressType {
	// TODO: which API to use to get the addresses?
	return map[string]corev1.NodeAddressType{
		"internal": corev1.NodeInternalIP,
		"external": corev1.NodeExternalIP,
	}
}

func (i *stackitInstance) Status() instance.Status {
	if i.server == nil {
		return instance.StatusUnknown
	}

	switch i.server.GetStatus() {
	case serverStatusActive:
		return instance.StatusRunning
	case serverStatusCreating:
		return instance.StatusCreating
	case serverStatusDeleted:
		return instance.StatusDeleted
	case serverStatusDeleting:
		return instance.StatusDeleting
	default:
		return instance.StatusUnknown
	}
}

func (p *provider) getConfig(provSpec clusterv1alpha1.ProviderSpec) (*Config, *providerconfig.Config, *stackittypes.RawConfig, error) {
	pconfig, err := providerconfig.GetConfig(provSpec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get config: %w", err)
	}

	rawConfig := &stackittypes.RawConfig{}
	if err = json.Unmarshal(pconfig.CloudProviderSpec.Raw, rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	config := &Config{
		BootVolumeSize:      rawConfig.BootVolumeSize,
		Labels:              rawConfig.Labels,
		ServiceAccountMails: rawConfig.ServiceAccountMails,
		SecurityGroups:      rawConfig.SecurityGroups,
		Volumes:             rawConfig.Volumes,
	}
	if rawConfig.Token.Value != "" {
		config.Token = rawConfig.Token.Value
	}
	if rawConfig.ProjectID.Value != "" {
		config.ProjectID = rawConfig.ProjectID.Value
	}
	if rawConfig.AvailabilityZone.Value != "" {
		config.AvailabilityZone = rawConfig.AvailabilityZone.Value
	}
	if rawConfig.MachineType.Value != "" {
		config.MachineType = rawConfig.MachineType.Value
	}
	if rawConfig.BootVolumeImageId.Value != "" {
		config.BootVolumeImageId = rawConfig.BootVolumeImageId.Value
	}
	if rawConfig.Network.Value != "" {
		config.Network = rawConfig.Network.Value
	}

	return config, pconfig, rawConfig, nil
}

func (p *provider) AddDefaults(_ *zap.SugaredLogger, spec clusterv1alpha1.MachineSpec) (clusterv1alpha1.MachineSpec, error) {
	// Add default values if needed
	return spec, nil
}

func (p *provider) Validate(ctx context.Context, log *zap.SugaredLogger, machinespec clusterv1alpha1.MachineSpec) error {
	config, _, _, err := p.getConfig(machinespec.ProviderSpec)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	if config.Token == "" {
		return fmt.Errorf("token is required")
	}
	if config.ProjectID == "" {
		return fmt.Errorf("projectId is required")
	}
	if config.AvailabilityZone == "" {
		return fmt.Errorf("availabilityZone is required")
	}
	if config.MachineType == "" {
		return fmt.Errorf("machineType is required")
	}

	log.Debug("Stackit provider validation passed")
	return nil
}

func (p *provider) Get(ctx context.Context, log *zap.SugaredLogger, machine *clusterv1alpha1.Machine, _ *cloudprovidertypes.ProviderData) (instance.Instance, error) {
	log.Debug("Getting stackit instance", "machine", machine.Spec.Name)

	return p.get(ctx, machine)
}

func (p *provider) Create(ctx context.Context, log *zap.SugaredLogger, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData, userdata string) (instance.Instance, error) {
	cfg, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	log.Info(
		"Creating stackit instance",
		"machine", machine.Spec.Name,
		"project", cfg.ProjectID,
	)

	// Create a new API client, that uses default authentication and configuration
	client, err := getClient(ctx, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("error creating API client: %w", err)
	}

	// Create a server
	csp := getCreateServerPayload(machine.Spec.Name, cfg)
	server, err := client.CreateServer(ctx, cfg.ProjectID).CreateServerPayload(csp).Execute()
	if err != nil {
		return nil, fmt.Errorf("error creating server: %w", err)
	}

	// Wait for creation of the server
	server, err = wait.CreateServerWaitHandler(ctx, client, cfg.ProjectID, *server.Id).WaitWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("error waiting server creation: %w", err)
	}

	return &stackitInstance{
		server: server,
	}, nil
}

func (p *provider) Cleanup(ctx context.Context, log *zap.SugaredLogger, machine *clusterv1alpha1.Machine, data *cloudprovidertypes.ProviderData) (bool, error) {
	log.Info("Cleaning up stackit instance", "machine", machine.Name)

	cfg, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return false, fmt.Errorf("failed to get config: %w", err)
	}

	client, err := getClient(ctx, cfg.Token)
	if err != nil {
		return false, fmt.Errorf("error creating API client: %w", err)
	}

	server, err := p.Get(ctx, log, machine, data)
	if err != nil {
		return false, fmt.Errorf("error getting server: %w", err)
	}

	projectId := cfg.ProjectID
	serverId := server.ID()

	// Delete a server
	err = client.DeleteServer(ctx, projectId, serverId).Execute()
	if err != nil {
		return false, fmt.Errorf("error deleting server: %w", err)
	}

	// Wait for deletion of the server
	_, err = wait.DeleteServerWaitHandler(ctx, client, projectId, serverId).WaitWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("error while waiting for server deletion: %w", err)
	}

	return true, nil
}

func (p *provider) MigrateUID(ctx context.Context, log *zap.SugaredLogger, machine *clusterv1alpha1.Machine, newUID types.UID) error {
	log.Info("Migrating UID for stackit instance",
		"machine", machine.Name,
		"oldUID", machine.UID,
		"newUID", newUID)

	cfg, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	server, err := p.get(ctx, machine)
	if err != nil {
		return fmt.Errorf("error getting server: %w", err)
	}

	client, err := getClient(ctx, cfg.Token)
	if err != nil {
		return fmt.Errorf("error getting API client: %w", err)
	}

	updateServerPayload := iaas.UpdateServerPayload{
		Labels: &map[string]interface{}{
			labelKeyMachineUID: string(newUID),
		},
	}

	_, err = client.UpdateServer(ctx, cfg.ProjectID, server.ID()).UpdateServerPayload(updateServerPayload).Execute()
	if err != nil {
		return fmt.Errorf("error updating server: %w", err)
	}

	return nil
}

func (p *provider) MachineMetricsLabels(machine *clusterv1alpha1.Machine) (map[string]string, error) {
	config, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	return map[string]string{
		"size":    config.MachineType,
		"region":  config.AvailabilityZone,
		"project": config.ProjectID,
	}, nil
}

func (p *provider) SetMetricsForMachines(machines clusterv1alpha1.MachineList) error {
	// No-op implementation for metrics
	return nil
}

func (p *provider) get(ctx context.Context, machine *clusterv1alpha1.Machine) (*stackitInstance, error) {
	cfg, _, _, err := p.getConfig(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider config: %w", err)
	}

	client, err := getClient(ctx, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("error creating API client: %w", err)
	}

	servers, err := client.ListServers(ctx, cfg.ProjectID).Execute()
	if err != nil {
		return nil, fmt.Errorf("error getting server list: %w", err)
	}

	for _, server := range *servers.Items {
		if *server.Name == machine.Spec.Name {
			return &stackitInstance{
				server: &server,
			}, nil
		}
	}
	return nil, cloudprovidererrors.ErrInstanceNotFound
}

func getCreateServerPayload(name string, cfg *Config) iaas.CreateServerPayload {
	csp := iaas.CreateServerPayload{
		Name:             utils.Ptr(name),
		AvailabilityZone: utils.Ptr(cfg.AvailabilityZone),
		MachineType:      utils.Ptr(cfg.MachineType),
		BootVolume: &iaas.CreateServerPayloadBootVolume{
			Size: utils.Ptr(cfg.BootVolumeSize),
			Source: &iaas.BootVolumeSource{
				Id:   utils.Ptr(cfg.BootVolumeImageId),
				Type: utils.Ptr("image"),
			},
		},
	}

	if cfg.Labels != nil && len(cfg.Labels) > 0 {
		csp.SetLabels(cfg.Labels)
	}
	if cfg.Volumes != nil && len(cfg.Volumes) > 0 {
		csp.SetVolumes(cfg.Volumes)
	}
	if cfg.ServiceAccountMails != nil && len(cfg.ServiceAccountMails) > 0 {
		csp.SetServiceAccountMails(cfg.ServiceAccountMails)
	}
	if cfg.SecurityGroups != nil && len(cfg.SecurityGroups) > 0 {
		csp.SetSecurityGroups(cfg.SecurityGroups)
	}
	if cfg.Network != "" {
		csp.Networking = &iaas.CreateServerPayloadNetworking{
			CreateServerNetworking: &iaas.CreateServerNetworking{
				NetworkId: utils.Ptr(cfg.Network),
			},
		}
	}
	return csp
}

func getClient(ctx context.Context, token string) (*iaas.APIClient, error) {
	client, err := iaas.NewAPIClient(
		config.WithToken(token),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating API client: %w", err)
	}

	return client, nil
}
