package smtpd

import "sync/atomic"

// counter is an atomic counter on a cache line of its own, so goroutines that
// count different things on different cores do not slow each other down.
type counter struct {
	v atomic.Int64
	_ [56]byte
}

func (c *counter) add(n int64) { c.v.Add(n) }
func (c *counter) inc()        { c.v.Add(1) }
func (c *counter) load() int64 { return c.v.Load() }

// stats are the counters of a Server. Every field is atomic, so the connections
// count themselves without taking a lock.
type stats struct {
	connsAccepted   counter
	connsRefused    counter
	connsActive     counter
	sessions        counter
	commands        counter
	protocolErrors  counter
	messages        counter
	messagesRefused counter
	dataBytes       counter
	rcptAccepted    counter
	rcptRefused     counter
	authSuccess     counter
	authFailure     counter
	authBlocked     counter
	tlsHandshakes   counter
	tlsFailures     counter
	earlyTalkers    counter
	timeouts        counter
	proxyHeaders    counter
	proxyFailures   counter
	panics          counter
}

// Stats is a reading of a Server's counters, in the form a metrics exporter
// wants: each field of a counter only ever grows, and ConnsActive is a gauge.
type Stats struct {
	// ConnsAccepted is the connections the server took from a listener.
	ConnsAccepted int64
	// ConnsRefused is the connections it answered with 421 and closed because a
	// limit was reached, or because a PROXY header was missing or not trusted.
	ConnsRefused int64
	// ConnsActive is the connections open now.
	ConnsActive int64
	// Sessions is the sessions the Backend was asked for.
	Sessions int64
	// Commands is the command lines read, including the ones refused.
	Commands int64
	// ProtocolErrors is the replies that refused a command for a syntax or
	// sequence reason or because the Backend refused it, which is what counts
	// toward MaxErrors.
	ProtocolErrors int64
	// Messages is the messages the Backend accepted.
	Messages int64
	// MessagesRefused is the messages that ended with an error reply.
	MessagesRefused int64
	// DataBytes is the bytes of message the Backend read.
	DataBytes int64
	// RcptAccepted and RcptRefused are the recipients the Backend accepted and
	// refused.
	RcptAccepted int64
	RcptRefused  int64
	// AuthSuccess, AuthFailure and AuthBlocked are the AUTH commands that
	// succeeded, that the Backend refused, and that were refused without
	// asking the Backend because the client had failed too often.
	AuthSuccess int64
	AuthFailure int64
	AuthBlocked int64
	// TLSHandshakes and TLSFailures are the handshakes that completed and the
	// ones that failed, for STARTTLS and for implicit TLS.
	TLSHandshakes int64
	TLSFailures   int64
	// EarlyTalkers is the clients that sent before the greeting.
	EarlyTalkers int64
	// Timeouts is the connections closed for being idle or too slow.
	Timeouts int64
	// ProxyHeaders and ProxyFailures are the PROXY protocol headers accepted
	// and the connections dropped for a bad or untrusted one.
	ProxyHeaders  int64
	ProxyFailures int64
	// Panics is the Backend panics the server recovered from.
	Panics int64
}

// Stats returns the counters now. It is safe to call from any goroutine.
func (s *Server) Stats() Stats {
	return Stats{
		ConnsAccepted:   s.st.connsAccepted.load(),
		ConnsRefused:    s.st.connsRefused.load(),
		ConnsActive:     s.st.connsActive.load(),
		Sessions:        s.st.sessions.load(),
		Commands:        s.st.commands.load(),
		ProtocolErrors:  s.st.protocolErrors.load(),
		Messages:        s.st.messages.load(),
		MessagesRefused: s.st.messagesRefused.load(),
		DataBytes:       s.st.dataBytes.load(),
		RcptAccepted:    s.st.rcptAccepted.load(),
		RcptRefused:     s.st.rcptRefused.load(),
		AuthSuccess:     s.st.authSuccess.load(),
		AuthFailure:     s.st.authFailure.load(),
		AuthBlocked:     s.st.authBlocked.load(),
		TLSHandshakes:   s.st.tlsHandshakes.load(),
		TLSFailures:     s.st.tlsFailures.load(),
		EarlyTalkers:    s.st.earlyTalkers.load(),
		Timeouts:        s.st.timeouts.load(),
		ProxyHeaders:    s.st.proxyHeaders.load(),
		ProxyFailures:   s.st.proxyFailures.load(),
		Panics:          s.st.panics.load(),
	}
}
