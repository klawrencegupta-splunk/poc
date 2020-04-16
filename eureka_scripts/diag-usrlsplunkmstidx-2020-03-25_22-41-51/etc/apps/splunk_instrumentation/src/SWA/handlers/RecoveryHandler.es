/**
 * Created by adrianj on 11/11/16.
 */
import Cache from '../services/Cache';

export default function RecoveryHandler(factory, options) {
    const cache = options.cache || new Cache();
    const queue = cache.retrieve();
    cache.clear();
    const cacheEvents = (events) => {
        if (events && Array.isArray(events)) {
            options.log('caching events:', events.length)
            cache.save(events);
        }
    };
    options.updateOptions({ eventRecovery: cacheEvents });

    if (queue && queue.length) {
        options.log('flushing from cache:', queue.length)
        queue.push('flush');
        queue.forEach(factory);
    }



    window.addEventListener('beforeunload', () => {
        factory('save');
    });

    // flush queue every 30 seconds
    setTimeout(() => factory('flush'), 30000);
}

RecoveryHandler.init = function (options) {


}