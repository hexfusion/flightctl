package spec

import (
	"container/heap"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/pkg/log"
)

type Item struct {
	Version int64
	Spec    *v1alpha1.RenderedDeviceSpec
	Retries int
}

func NewItem(data *v1alpha1.RenderedDeviceSpec, version int64) *Item {
	return &Item{
		Spec:    data,
		Version: version,
	}
}

type Queue struct {
	heap           ItemHeap
	items          map[int64]*Item
	failedVersions map[int64]struct{}
	maxRetries     int
	maxSize        int

	log *log.PrefixLogger
}

func NewQueue(log *log.PrefixLogger, maxRetries, maxSize int) *Queue {
	return &Queue{
		heap:           make(ItemHeap, 0),
		items:          make(map[int64]*Item),
		failedVersions: make(map[int64]struct{}),
		maxRetries:     maxRetries,
		maxSize:        maxSize,
		log:            log,
	}
}

func (q *Queue) Add2(item *Item) {
	version := item.Version
	if _, ok := q.failedVersions[version]; ok {
		q.log.Debugf("Skipping add for failed version: %v\n", version)
		return
	}

	if _, exists := q.items[version]; exists {
		q.log.Debugf("Version %v is already in the queue. Skipping add.\n", version)
		return
	}

	q.items[version] = item
	heap.Push(&q.heap, item)

	if q.heap.Len() > q.maxSize {
		// Remove the item with the lowest version
		removedItem := heap.Pop(&q.heap).(*Item)
		delete(q.items, removedItem.Version)
		q.log.Debugf("Queue exceeded max size, removed lowest version: %v\n", removedItem.Version)
	}
}

func (q *Queue) Add(item *Item) {
	version := item.Version
	if _, ok := q.failedVersions[version]; ok {
		q.log.Debugf("Skipping add for failed version: %v\n", version)
		return
	}

	if _, exists := q.items[version]; exists {
		q.log.Debugf("Version %v is already in the queue. Skipping add.\n", version)
		return
	}

	q.items[version] = item
	heap.Push(&q.heap, item)

	if len(q.items) > q.maxSize {
		// Remove the item with the lowest version
		removedItem := heap.Pop(&q.heap).(*Item)
		delete(q.items, removedItem.Version)
		q.log.Debugf("Queue exceeded max size, removed version: %v\n", removedItem.Version)
	}
}

func (q *Queue) Get() (*Item, bool) {
	if q.heap.Len() == 0 {
		return nil, false
	}

	// pop off the lowest version
	item := heap.Pop(&q.heap).(*Item)

	return item, true
}

func (q *Queue) Requeue(version int64) {
	item, ok := q.items[version]
	if !ok {
		q.log.Debugf("Version %v not found in queue, skipping requeue", version)
		return
	}

	// remove if max retries are exceeded
	if item.Retries >= q.maxRetries {
		q.log.Debugf("Max retries reached for version: %v", item.Version)
		q.SetVersionFailed(version)
		q.Forget(version)
		return
	}

	item.Retries++

	// clean up the heap to reduce duplicates
	for i, heapItem := range q.heap {
		if heapItem.Version == version {
			q.log.Debugf("Removing version %v from heap before requeue", version)
			heap.Remove(&q.heap, i)
			break
		}
	}

	q.log.Debugf("Requeuing version %v with retries: %d", version, item.Retries)
	heap.Push(&q.heap, item)

	// ensure maxSize of the queue
	if len(q.items) > q.maxSize {
		removed := heap.Pop(&q.heap).(*Item)
		q.log.Debugf("Queue exceeded max size removed version: %v", removed.Version)
		delete(q.items, removed.Version) // Forget the removed item from the items map
	}
}

func (q *Queue) Forget(version int64) {
	if _, ok := q.items[version]; ok {
		q.log.Debugf("Forgetting version %v\n", version)
		delete(q.items, version)
	}

	// ensure heap removal
	for i, heapItem := range q.heap {
		if heapItem.Version == version {
			q.log.Debugf("Removing version %v from heap during Forget\n", version)
			heap.Remove(&q.heap, i)
			break
		}
	}
}
func (q *Queue) Len() int {
	return len(q.items)
}

func (q *Queue) IsEmpty() bool {
	return q.Len() == 0
}

func (q *Queue) SetVersionFailed(version int64) {
	q.log.Debugf("Setting version %v as failed\n", version)
	q.failedVersions[version] = struct{}{}
}

func (q *Queue) IsVersionFailed(version int64) bool {
	_, ok := q.failedVersions[version]
	return ok
}

// ItemHeap is a simple min-heap of Items
type ItemHeap []*Item

func (h ItemHeap) Len() int {
	return len(h)
}

func (h ItemHeap) Less(i, j int) bool {
	return h[i].Version < h[j].Version
}

func (h ItemHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *ItemHeap) Push(x interface{}) {
	*h = append(*h, x.(*Item))
}

func (h *ItemHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}
