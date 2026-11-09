package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/italypaleale/francis/builtin/ratelimit"
)

// rateLimitTimeout bounds how long a rate limit check can take before the call is allowed through
const rateLimitTimeout = 2 * time.Second

// RateLimiter throttles calls by key, such as a client IP or a user ID
// It's backed by a Francis rate limiter, so all replicas share the same budget for each key
type RateLimiter struct {
	name string
	host *Host
	svc  *ratelimit.RateLimitService
	log  *slog.Logger
}

// NewRateLimiter registers a rate limiter that admits rate calls per period for each key
// The bucket holds rate tokens, so a fresh key can make rate calls at once, and then one more each time a token refills
// It must be called before Run
func (h *Host) NewRateLimiter(name string, rate int, per time.Duration) (*RateLimiter, error) {
	rl, err := ratelimit.New(name,
		ratelimit.WithRate(rate),
		ratelimit.WithPer(per),
		ratelimit.WithBurst(rate),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter '%s': %w", name, err)
	}

	err = h.host.RegisterBuiltInActor(rl)
	if err != nil {
		return nil, fmt.Errorf("failed to register rate limiter '%s': %w", name, err)
	}

	return &RateLimiter{
		name: name,
		host: h,
		svc:  rl.Service(h.host.Service()),
		log:  h.log.With(slog.String("rateLimiter", name)),
	}, nil
}

// Allow reports whether a call for the key is admitted, and if not, how long the caller should wait before retrying
// Rate limiters fail open
func (r *RateLimiter) Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration) {
	err := r.host.checkRunning()
	if err != nil {
		r.log.WarnContext(ctx, "Rate limit check skipped, allowing the call",
			slog.String("key", key),
			slog.Any("error", err),
		)
		return true, 0
	}

	allowCtx, cancel := context.WithTimeout(ctx, rateLimitTimeout)
	defer cancel()

	allowed, retryAfter, err = r.svc.Allow(allowCtx, key)
	if err != nil {
		// When the caller's context is done, the call won't go anywhere anyways, so there's nothing to report
		if ctx.Err() == nil {
			r.log.WarnContext(ctx, "Rate limit check failed, allowing the call",
				slog.String("key", key),
				slog.Any("error", err),
				slog.Bool("timeout", errors.Is(err, context.DeadlineExceeded)),
			)
		}
		return true, 0
	}

	return allowed, retryAfter
}
