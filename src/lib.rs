extern crate hyper;
extern crate time;
extern crate url;

mod net_traits;

mod fetch {
    mod request;
    mod response;
    mod cors_cache;
}

#[test]
fn it_works() {
}
