package progress

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
)

var (
	t    *tea.Program
	Skip bool
)

type progressWriter struct {
	total      int
	downloaded int
	file       *os.File
	reader     io.Reader
	onProgress func(float64)
}

func (pw *progressWriter) Start() {
	// TeeReader calls pw.Write() each time a new response is received
	_, err := io.Copy(pw.file, io.TeeReader(pw.reader, pw))
	if err != nil {
		t.Send(progressErrMsg{err})
	}
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	pw.downloaded += len(p)

	if pw.downloaded == pw.total {
		t.Send(true)
	}

	if pw.total > 0 && pw.onProgress != nil {
		pw.onProgress(float64(pw.downloaded) / float64(pw.total))
	}

	return len(p), nil
}

func Download(resp *http.Response, file *os.File, status string) {
	if Skip {
		return
	}

	pw := &progressWriter{
		total:  int(resp.ContentLength),
		file:   file,
		reader: resp.Body,
		onProgress: func(ratio float64) {
			t.Send(progressMsg(ratio))
		},
	}
	m := model{
		pw:       pw,
		progress: progress.New(progress.WithDefaultGradient()),
		status:   status,
		done:     false,
	}

	t = tea.NewProgram(m)

	go pw.Start()

	if _, err := t.Run(); err != nil {
		fmt.Println("error running program:", err)
		os.Exit(1)
	}
}

func Extract(reader io.Reader, total int, file *os.File, status string) {
	if Skip {
		return
	}

	pw := &progressWriter{
		total:  total,
		file:   file,
		reader: reader,
		onProgress: func(ratio float64) {
			t.Send(progressMsg(ratio))
		},
	}

	m := model{
		pw:       pw,
		progress: progress.New(progress.WithDefaultGradient()),
		status:   status,
		done:     false,
	}

	t = tea.NewProgram(m)

	go pw.Start()

	if _, err := t.Run(); err != nil {
		fmt.Println("error running program:", err)
		os.Exit(1)
	}
}
