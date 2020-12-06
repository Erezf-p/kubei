package types

import (
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

type ScanErrType string

const (
	ScanErrTypeDockle ScanErrType = "ScanErrTypeDockle"
	ScanErrTypeVul    ScanErrType = "ScanErrTypeVulnerability"
	ScanErrTypeJob    ScanErrType = "ScanErrTypeJob"
)

type ScanErrMsg struct {
	Msg        string
	ErrMsgType ScanErrType
}
