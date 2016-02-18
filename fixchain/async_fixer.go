package fixchain

import (
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/certificate-transparency/go/x509"
)

// AsyncFixer contains methods to asynchronously fix certificate chains and
// properties to store information about each attempt that is made to fix a
// certificate chain.
type AsyncFixer struct {
	toFix  chan *toFix
	chains chan<- []*x509.Certificate // Chains successfully fixed by the fixer
	errors chan<- *FixError

	active uint32
	// Counters may not be entirely accurate due to non-atomicity
	reconstructed    uint
	notReconstructed uint
	fixed            uint
	notFixed         uint
	skipped          uint
	alreadyDone      uint

	wg    sync.WaitGroup
	cache *urlCache
	done  *lockedMap
}

// QueueChain adds the given cert and chain to the queue to be fixed by the
// fixer, with respect to the given roots.
func (f *AsyncFixer) QueueChain(cert *x509.Certificate, chain []*x509.Certificate, roots *x509.CertPool) {
	d := &dedupedChain{}
	for _, c := range chain {
		d.addCert(c)
	}

	f.toFix <- &toFix{cert: cert, chain: d, roots: roots, cache: f.cache}
}

// Wait for all the fixer workers to finish.
func (f *AsyncFixer) Wait() {
	close(f.toFix)
	f.wg.Wait()
}

func (f *AsyncFixer) updateCounters(ferrs []*FixError) {
	var verifyFailed bool
	var fixFailed bool
	for _, ferr := range ferrs {
		switch ferr.Type {
		case VerifyFailed:
			verifyFailed = true
		case FixFailed:
			fixFailed = true
		}
	}
	// No errors --> reconstructed
	// VerifyFailed --> notReconstructed
	// VerifyFailed but no FixFailed --> fixed
	// VerifyFailed and FixFailed --> notFixed
	if verifyFailed {
		f.notReconstructed++
		// FixFailed error will only be present if a VerifyFailed error is, as
		// fixChain() is only called if constructChain() fails.
		if fixFailed {
			f.notFixed++
			return
		}
		f.fixed++
		return
	}
	f.reconstructed++
}

func (f *AsyncFixer) fixServer() {
	defer f.wg.Done()

	for fix := range f.toFix {
		atomic.AddUint32(&f.active, 1)
		chains, ferrs := fix.handleChain()
		f.updateCounters(ferrs)
		for _, ferr := range ferrs {
			f.errors <- ferr
		}
		for _, chain := range chains {
			f.chains <- chain
		}
		atomic.AddUint32(&f.active, ^uint32(0))
	}
}

func (f *AsyncFixer) newFixServerPool(workerCount int) {
	for i := 0; i < workerCount; i++ {
		f.wg.Add(1)
		go f.fixServer()
	}
}

func (f *AsyncFixer) logStats() {
	t := time.NewTicker(time.Second)
	go func() {
		for _ = range t.C {
			log.Printf("fixers: %d active, "+
				"%d reconstructed, %d not reconstructed, "+
				"%d fixed, %d not fixed, %d skipped, %d already done",
				f.active, f.reconstructed, f.notReconstructed,
				f.fixed, f.notFixed, f.skipped, f.alreadyDone)
		}
	}()
}

// NewAsyncFixer creates a new asynchronous fixer and starts up a pool of
// workerCount workers.  Errors are pushed to the errors channel, and fixed
// chains are pushed to the chains channel.  client is used to try to get any
// missing certificates that are needed when attempting to fix chains.
func NewAsyncFixer(workerCount int, chains chan<- []*x509.Certificate, errors chan<- *FixError, client *http.Client, logStats bool) *AsyncFixer {
	f := &AsyncFixer{
		toFix:  make(chan *toFix),
		chains: chains,
		errors: errors,
		cache:  newURLCache(client, logStats),
		done:   newLockedMap(),
	}

	f.newFixServerPool(workerCount)
	if logStats {
		f.logStats()
	}
	return f
}
