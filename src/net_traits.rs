use hyper::header::{ContentType, Headers};
use hyper::http::RawStatus;
use hyper::mime::{Attr, Mime};
use hyper::status::StatusCode;
use std::cell::RefCell;
use std::rc::Rc;
use url::Url;

/// Interface for observing the final response for an asynchronous fetch operation.
pub trait AsyncFetchListener {
    fn response_available(&self, response: Response);
}

/// [Response type](https://fetch.spec.whatwg.org/#concept-response-type)
#[derive(Clone, PartialEq, Copy)]
pub enum ResponseType {
    Basic,
    CORS,
    Default,
    Error,
    Opaque,
    OpaqueRedirect
}

/// [Response termination reason](https://fetch.spec.whatwg.org/#concept-response-termination-reason)
#[derive(Clone, Copy)]
pub enum TerminationReason {
    EndUserAbort,
    Fatal,
    Timeout
}

/// The response body can still be pushed to after fetch
/// This provides a way to store unfinished response bodies
#[derive(Clone)]
pub enum ResponseBody {
    Empty, // XXXManishearth is this necessary, or is Done(vec![]) enough?
    Receiving(Vec<u8>),
    Done(Vec<u8>),
}

pub enum ResponseMsg {
    Chunk(Vec<u8>),
    Finished,
    Errored
}

/// A [Response](https://fetch.spec.whatwg.org/#concept-response) as defined by the Fetch spec
#[derive(Clone)]
pub struct Response {
    pub response_type: ResponseType,
    pub termination_reason: Option<TerminationReason>,
    pub url: Option<Url>,
    pub url_list: Vec<Url>,
    /// `None` can be considered a StatusCode of `0`.
    pub status: Option<StatusCode>,
    pub headers: Headers,
    pub body: ResponseBody,
    /// [Internal response](https://fetch.spec.whatwg.org/#concept-internal-response), only used if the Response
    /// is a filtered response
    pub internal_response: Option<Rc<RefCell<Response>>>,
}

impl Response {
    pub fn network_error() -> Response {
        Response {
            response_type: ResponseType::Error,
            termination_reason: None,
            url: None,
            url_list: vec![],
            status: None,
            headers: Headers::new(),
            body: ResponseBody::Empty,
            internal_response: None
        }
    }

    pub fn is_network_error(&self) -> bool {
        match self.response_type {
            ResponseType::Error => true,
            _ => false
        }
    }
}

/// Metadata about a loaded resource, such as is obtained from HTTP headers.
#[derive(Clone)]
pub struct Metadata {
    /// Final URL after redirects.
    pub final_url: Url,

    /// MIME type / subtype.
    pub content_type: Option<(ContentType)>,

    /// Character set.
    pub charset: Option<String>,

    /// Headers
    pub headers: Option<Headers>,

    /// HTTP Status
    pub status: Option<RawStatus>,
}

impl Metadata {
    /// Metadata with defaults for everything optional.
    pub fn default(url: Url) -> Self {
        Metadata {
            final_url:    url,
            content_type: None,
            charset:      None,
            headers: None,
            // https://fetch.spec.whatwg.org/#concept-response-status-message
            status: Some(RawStatus(200, "OK".into())),
        }
    }

    /// Extract the parts of a Mime that we care about.
    pub fn set_content_type(&mut self, content_type: Option<&Mime>) {
        match content_type {
            None => (),
            Some(mime) => {
                self.content_type = Some(ContentType(mime.clone()));
                let &Mime(_, _, ref parameters) = mime;
                for &(ref k, ref v) in parameters {
                    if &Attr::Charset == k {
                        self.charset = Some(v.to_string());
                    }
                }
            }
        }
    }
}
