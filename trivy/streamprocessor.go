package trivy

type StreamProcessor interface {
	Process() error
}
