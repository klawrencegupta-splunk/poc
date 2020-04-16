export default function PageHandler(factory, options) {
    let event = {
        type: 'pageview',
    };
    return factory(event);
}
