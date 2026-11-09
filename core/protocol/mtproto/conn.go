package mtproto

import "net"

// closeWriter / closeReader are satisfied by *net.TCPConn and most wrapped
// stream conns in sing-box.
type closeWriter interface{ CloseWrite() error }
type closeReader interface{ CloseRead() error }

// essentialsConn adapts a net.Conn to github.com/9seconds/mtg/v2/essentials.Conn
// which additionally requires CloseRead / CloseWrite. When the underlying conn
// does not support half-close, we fall back to a full Close so mtg's relay can
// still tear the stream down.
type essentialsConn struct {
	net.Conn
}

func (c essentialsConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c essentialsConn) CloseRead() error {
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return c.Conn.Close()
}
