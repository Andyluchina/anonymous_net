package datastruct

type ClientStats struct {
	ClientID                     int
	InitalReportingTime          float64
	SecreteShareTime             float64
	ShuffleTime                  float64
	RevealTime                   float64
	FTTime                       float64
	Entry                        []byte
	UploadBytesInitalReporting   int
	DownloadBytesInitalReporting int
	UploadBytesSecreteShare      int
	DownloadBytesSecreteShare    int
	UploadBytesShuffle           int
	DownloadBytesShuffle         int
	UploadBytesReveal            int
	DownloadBytesReveal          int
	UploadBytesFT                int
	DownloadBytesFT              int
	AuditorZKCheckTime           float64
}

type AuditorReport struct {
	TotalClients       uint32
	MaxSitOut          uint32
	Shufflers          uint32
	ShufflerUnderKKeys uint32
	CalculatedEntries  [][][]byte
	TotalRunTime       float64
	PerClientCPU       []AuditorClientCPUReport
}

type AuditorClientCPUReport struct {
	ID                    int
	InitialReportingTime  float64
	SecreteSharing        float64
	ShuffleTime           float64
	RevealTime            float64
	FaultToleranceTime    float64
	AuditorEncryptionTime float64
}

type TestRun struct {
	Auditor AuditorReport
	Clients []ClientStats
}

type RunTask struct {
	TotalClients          uint32
	MaxSitOut             uint32
	Shuffler              uint32
	Shuffler_under_k_keys uint32
}

type ReportStatsReply struct {
	Status bool
}
