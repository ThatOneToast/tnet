#[macro_export]
macro_rules! wrap_handler {
    ($func:expr) => {
        Arc::new(move |socket, payload, pools, resources| {
            Box::pin($func(socket, payload, pools, resources)) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
        })
    };
}
