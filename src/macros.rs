#[macro_export]
macro_rules! wrap_handler {
    ($func:expr) => {
        Arc::new(move |socket, payload| {
            Box::pin($func(socket, payload)) as Pin<Box<dyn Future<Output = ()> + Send + 'static>>
        })
    };
}
