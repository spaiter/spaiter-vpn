package daemon

import (
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/spaiter/spaiter-vpn/core/experimental/deprecated"
)

var _ deprecated.Manager = (*deprecatedManager)(nil)

type deprecatedManager struct {
	access sync.Mutex
	notes  []deprecated.Note
}

func (m *deprecatedManager) ReportDeprecated(feature deprecated.Note) {
	m.access.Lock()
	defer m.access.Unlock()
	m.notes = common.Uniq(append(m.notes, feature))
}

func (m *deprecatedManager) Get() []deprecated.Note {
	m.access.Lock()
	defer m.access.Unlock()
	notes := m.notes
	m.notes = nil
	return notes
}
