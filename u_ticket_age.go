package tls

import "time"

// obfuscatedTicketAge is the obfuscated_ticket_age for a PSK identity built
// from a session received at createdAt (seconds since the epoch), sent at now.
//
// Go measures the age to the millisecond. BoringSSL does not:
//
//	OPENSSL_timeval now = ssl_ctx_get_current_time(ssl->ctx.get());
//	uint32_t ticket_age = 1000 * (now.tv_sec - session->time);
//	uint32_t obfuscated_ticket_age = ticket_age + session->ticket_age_add;
//
// session->time is whole seconds, the same as createdAt, so the age a
// BoringSSL client reports is always a whole number of seconds. The server
// removes ticket_age_add and reads the plain age, which makes a millisecond
// remainder a per-resumption tell for any profile mirroring a BoringSSL
// client. TicketAgeWholeSeconds selects the BoringSSL arithmetic.
func (c *Config) obfuscatedTicketAge(now time.Time, createdAt uint64, ageAdd uint32) uint32 {
	if c.TicketAgeWholeSeconds {
		return uint32(1000*(now.Unix()-int64(createdAt))) + ageAdd
	}
	ticketAge := now.Sub(time.Unix(int64(createdAt), 0))
	return uint32(ticketAge/time.Millisecond) + ageAdd
}
