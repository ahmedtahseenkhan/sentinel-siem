package response

type Action interface {
	Name() string
	Description() string
}

type FirewallDropAction struct{}

func (a *FirewallDropAction) Name() string        { return "firewall-drop" }
func (a *FirewallDropAction) Description() string { return "Block IP address via firewall rules" }

type KillProcessAction struct{}

func (a *KillProcessAction) Name() string        { return "kill-process" }
func (a *KillProcessAction) Description() string { return "Kill a running process by PID" }

type RestartServiceAction struct{}

func (a *RestartServiceAction) Name() string        { return "restart-service" }
func (a *RestartServiceAction) Description() string { return "Restart a system service" }

type DisableAccountAction struct{}

func (a *DisableAccountAction) Name() string        { return "disable-account" }
func (a *DisableAccountAction) Description() string { return "Disable a user account" }
