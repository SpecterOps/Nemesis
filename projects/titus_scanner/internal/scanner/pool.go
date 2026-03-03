package scanner

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/titus"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
)

// Pool manages a fixed set of Scanner instances for safe concurrent use.
// The Titus PortableRegexpMatcher is NOT safe for concurrent use, so each
// concurrent scan must use its own Scanner instance. The pool hands out
// scanners via a buffered channel (used as a semaphore), guaranteeing
// that no two goroutines share the same underlying matcher.
type Pool struct {
	scanners chan *Scanner
	size     int
}

// NewPool creates a pool of n independent Scanner instances, each backed
// by its own titus.Scanner compiled from the given rules.
func NewPool(n int, opts Options, createScanner func() (*titus.Scanner, error)) (*Pool, error) {
	if n < 1 {
		n = 1
	}

	pool := &Pool{
		scanners: make(chan *Scanner, n),
		size:     n,
	}

	for i := 0; i < n; i++ {
		ts, err := createScanner()
		if err != nil {
			// Close any scanners already created
			pool.Close()
			return nil, fmt.Errorf("failed to create scanner instance %d: %w", i, err)
		}
		pool.scanners <- New(ts, opts)
	}

	return pool, nil
}

// Acquire blocks until a Scanner is available and returns it.
// The caller MUST call Release when done.
func (p *Pool) Acquire() *Scanner {
	return <-p.scanners
}

// Release returns a Scanner to the pool.
func (p *Pool) Release(s *Scanner) {
	p.scanners <- s
}

// ScanFile acquires a scanner, scans the file, and releases it.
func (p *Pool) ScanFile(ctx context.Context, filePath string, originalPath string) (*models.ScanResult, error) {
	sc := p.Acquire()
	defer p.Release(sc)
	return sc.ScanFile(ctx, filePath, originalPath)
}

// RuleCount returns the number of rules loaded (same across all instances).
func (p *Pool) RuleCount() int {
	// Peek at one scanner without blocking by using a temporary acquire/release.
	// All scanners have the same rule count.
	sc := p.Acquire()
	count := sc.RuleCount()
	p.Release(sc)
	return count
}

// Size returns the number of scanners in the pool.
func (p *Pool) Size() int {
	return p.size
}

// Close releases all scanner resources.
func (p *Pool) Close() error {
	close(p.scanners)
	var firstErr error
	for sc := range p.scanners {
		if err := sc.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
