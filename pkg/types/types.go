package types

import (
	"errors"
	dockle_types "github.com/Portshift/dockle/pkg/types"
	"github.com/Portshift/klar/clair"
)

type ScanProgress struct {
	ImagesToScan          uint32
	ImagesStartedToScan   uint32
	ImagesCompletedToScan uint32
}

type ImageScanResult struct {
	PodName               string
	PodNamespace          string
	ImageName             string
	ContainerName         string
	ImageHash             string
	PodUid                string
	Vulnerabilities       []*clair.Vulnerability
	DockerfileScanResults dockle_types.AssessmentMap
	Success               bool
	ScanErrors            []*ScanErrMsg
}

type ScanResults struct {
	ImageScanResults []*ImageScanResult
	Progress         ScanProgress
}

type ScanErrorSource string

const (
	ScanErrSourceDockle ScanErrorSource = "ScanErrSourceDockle"
	ScanErrSourceVul    ScanErrorSource = "ScanErrSourceVulnerability"
	ScanErrSourceJob    ScanErrorSource = "ScanErrSourceJob"
)

type ScanErrMsg struct {
	Error         error
	ScanErrSource ScanErrorSource
}

var ErrorUnauthorized = errors.New("unauthorized")
var ErrorJobRun = errors.New("failed to run job")
var ErrorScanTimeout = errors.New("job timed out")
