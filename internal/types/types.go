package types

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
}

type Directive struct {
	Instruction string
	Args        string
	Line        int
}

type ComposeService struct {
	Image       string   `yaml:"image"`
	Privileged  bool     `yaml:"privileged"`
	NetworkMode string   `yaml:"network_mode"`
	Volumes     []string `yaml:"volumes"`
	Ports       []string `yaml:"ports"`
	Environment []string `yaml:"environment"`
	User        string   `yaml:"user"`
	MemLimit    string   `yaml:"mem_limit"`
	CPUs        string   `yaml:"cpus"`
	Pid         string   `yaml:"pid"`
	Ipc         string   `yaml:"ipc"`
	SecurityOpt []string `yaml:"security_opt"`
}

type ComposeFile struct {
	Services map[string]ComposeService
}

type ParseContext struct {
	FilePath    string
	Directives  []Directive
	ComposeData *ComposeFile
}
