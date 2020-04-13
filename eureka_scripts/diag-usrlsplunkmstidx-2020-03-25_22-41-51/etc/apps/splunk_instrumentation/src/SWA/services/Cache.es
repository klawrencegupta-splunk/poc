export default class Cache {
    constructor(options) {
        this._options = Object.assign({}, options, {
            cacheKey: 'swa_js_default_cache',
            queueFailureMax: 200,
        });
    }

    save(data) {
        const queue = this.retrieve();
        for (let i = 0; i < data.length; i++) {
            const dto = data[i];
            queue.push(dto);
        }
        this._update(queue);
    }

    retrieve() {
        const data = JSON.parse(localStorage.getItem(this._options.cacheKey)) || { queue: [] };
        const queue = data.queue;
        return queue;
    }

    clear() {
        this._update([]);
    }

    _update(queue) {
        while (queue.length > this._options.queueFailureMax) {
            queue.shift(); 
        }
        try {
            localStorage.setItem(this._options.cacheKey, JSON.stringify({ "queue": queue }));
        } catch (e) {
            if (this._options.log) this._options.log(" localStorage is full.");
        }
    }
}
