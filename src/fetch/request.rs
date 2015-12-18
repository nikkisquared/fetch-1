/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use fetch::cors_cache::{CORSCache, CacheRequestDetails};
use fetch::response::ResponseMethods;
use hyper::header::{Accept, IfMatch, IfRange, IfUnmodifiedSince, Location};
use hyper::header::{AcceptLanguage, ContentLanguage, HeaderView};
use hyper::header::{ContentType, Header, Headers, IfModifiedSince, IfNoneMatch};
use hyper::header::{QualityItem, q, qitem};
use hyper::method::Method;
use hyper::mime::{Attr, Mime, SubLevel, TopLevel, Value};
use hyper::status::StatusCode;
use net_traits::{AsyncFetchListener, Response};
use net_traits::{ResponseType, Metadata};
use std::ascii::AsciiExt;
use std::cell::RefCell;
use std::rc::Rc;
use std::str::FromStr;
use std::thread;
use url::{Url, UrlParser};

fn spawn_named<F>(name: String, f: F)
    where F: FnOnce() + Send + 'static
{
    let builder = thread::Builder::new().name(name);
    builder.spawn(f).unwrap();
}

/// A [request context](https://fetch.spec.whatwg.org/#concept-request-context)
#[derive(Copy, Clone, PartialEq)]
pub enum Context {
    Audio, Beacon, CSPreport, Download, Embed, Eventsource,
    Favicon, Fetch, Font, Form, Frame, Hyperlink, IFrame, Image,
    ImageSet, Import, Internal, Location, Manifest, MetaRefresh, Object,
    Ping, Plugin, Prefetch, PreRender, Script, ServiceWorker, SharedWorker,
    Subresource, Style, Track, Video, Worker, XMLHttpRequest, XSLT
}

/// A [request context frame type](https://fetch.spec.whatwg.org/#concept-request-context-frame-type)
#[derive(Copy, Clone, PartialEq)]
pub enum ContextFrameType {
    Auxiliary,
    TopLevel,
    Nested,
    ContextNone
}

/// A [referer](https://fetch.spec.whatwg.org/#concept-request-referrer)
pub enum Referer {
    NoReferer,
    Client,
    RefererUrl(Url)
}

/// A [request mode](https://fetch.spec.whatwg.org/#concept-request-mode)
#[derive(Copy, Clone, PartialEq)]
pub enum RequestMode {
    SameOrigin,
    NoCORS,
    CORSMode,
    ForcedPreflightMode
}

/// Request [credentials mode](https://fetch.spec.whatwg.org/#concept-request-credentials-mode)
#[derive(Copy, Clone, PartialEq)]
pub enum CredentialsMode {
    Omit,
    CredentialsSameOrigin,
    Include
}

/// [Cache mode](https://fetch.spec.whatwg.org/#concept-request-cache-mode)
#[derive(Copy, Clone, PartialEq)]
pub enum CacheMode {
    Default,
    NoStore,
    Reload,
    NoCache,
    ForceCache,
    OnlyIfCached
}

/// [Redirect mode](https://fetch.spec.whatwg.org/#concept-request-redirect-mode)
#[derive(Copy, Clone, PartialEq)]
pub enum RedirectMode {
    Follow,
    Error,
    Manual
}

/// [Response tainting](https://fetch.spec.whatwg.org/#concept-request-response-tainting)
#[derive(Copy, Clone, PartialEq)]
pub enum ResponseTainting {
    Basic,
    CORSTainting,
    Opaque
}

/// A [Request](https://fetch.spec.whatwg.org/#requests) as defined by the Fetch spec
pub struct Request {
    pub method: Method,
    // Use the last method on url_list to act as spec url field
    pub url_list: Vec<Url>,
    pub headers: Headers,
    pub unsafe_request: bool,
    pub body: Option<Vec<u8>>,
    pub preserve_content_codings: bool,
    // pub client: GlobalRef, // XXXManishearth copy over only the relevant fields of the global scope,
                              // not the entire scope to avoid the libscript dependency
    pub is_service_worker_global_scope: bool,
    pub skip_service_worker: bool,
    pub context: Context,
    pub context_frame_type: ContextFrameType,
    pub origin: Option<Url>, // FIXME: Use Url::Origin
    pub force_origin_header: bool,
    pub omit_origin_header: bool,
    pub same_origin_data: bool,
    pub referer: Referer,
    pub authentication: bool,
    pub sync: bool,
    pub mode: RequestMode,
    pub credentials_mode: CredentialsMode,
    pub use_url_credentials: bool,
    pub cache_mode: CacheMode,
    pub redirect_mode: RedirectMode,
    pub redirect_count: usize,
    pub response_tainting: ResponseTainting,
    pub cache: Option<Box<CORSCache + Send>>
}

impl Request {
    pub fn new(url: Url, context: Context, is_service_worker_global_scope: bool) -> Request {
         Request {
            method: Method::Get,
            url_list: vec![url],
            headers: Headers::new(),
            unsafe_request: false,
            body: None,
            preserve_content_codings: false,
            is_service_worker_global_scope: is_service_worker_global_scope,
            skip_service_worker: false,
            context: context,
            context_frame_type: ContextFrameType::ContextNone,
            origin: None,
            force_origin_header: false,
            omit_origin_header: false,
            same_origin_data: false,
            referer: Referer::Client,
            authentication: false,
            sync: false,
            mode: RequestMode::NoCORS,
            credentials_mode: CredentialsMode::Omit,
            use_url_credentials: false,
            cache_mode: CacheMode::Default,
            redirect_mode: RedirectMode::Follow,
            redirect_count: 0,
            response_tainting: ResponseTainting::Basic,
            cache: None
        }
    }

    fn get_last_url_string(&self) -> String {
        self.url_list.last().unwrap().serialize()
    }

    fn current_url(&self) -> Option<Url> {
        self.url_list.last()
    }
}

fn fetch_async(Rc<RefCell<Request>>, cors_flag: bool, listener: Box<AsyncFetchListener + Send>) {
    spawn_named(format!("fetch for {:?}", request.get_last_url_string()), move || {
        let res = request.fetch(cors_flag);
        listener.response_available(res);
    })
}

/// [Fetch](https://fetch.spec.whatwg.org#concept-fetch)
fn fetch(Rc<RefCell<Request>>, cors_flag: bool) -> Response {

    // Step 1
    if request.context != Context::Fetch && !request.headers.has::<Accept>() {

        // Substep 1
        let value = match request.context {

            Context::Favicon | Context::Image | Context::ImageSet
                => vec![qitem(Mime(TopLevel::Image, SubLevel::Png, vec![])),
                    // FIXME: This should properly generate a MimeType that has a
                    // SubLevel of svg+xml (https://github.com/hyperium/mime.rs/issues/22)
                    qitem(Mime(TopLevel::Image, SubLevel::Ext("svg+xml".to_owned()), vec![])),
                    QualityItem::new(Mime(TopLevel::Image, SubLevel::Star, vec![]), q(0.8)),
                    QualityItem::new(Mime(TopLevel::Star, SubLevel::Star, vec![]), q(0.5))],

            Context::Form | Context::Frame | Context::Hyperlink |
            Context::IFrame | Context::Location | Context::MetaRefresh |
            Context::PreRender
                => vec![qitem(Mime(TopLevel::Text, SubLevel::Html, vec![])),
                    // FIXME: This should properly generate a MimeType that has a
                    // SubLevel of xhtml+xml (https://github.com/hyperium/mime.rs/issues/22)
                    qitem(Mime(TopLevel::Application, SubLevel::Ext("xhtml+xml".to_owned()), vec![])),
                    QualityItem::new(Mime(TopLevel::Application, SubLevel::Xml, vec![]), q(0.9)),
                    QualityItem::new(Mime(TopLevel::Star, SubLevel::Star, vec![]), q(0.8))],

            Context::Internal if request.context_frame_type != ContextFrameType::ContextNone
                => vec![qitem(Mime(TopLevel::Text, SubLevel::Html, vec![])),
                    // FIXME: This should properly generate a MimeType that has a
                    // SubLevel of xhtml+xml (https://github.com/hyperium/mime.rs/issues/22)
                    qitem(Mime(TopLevel::Application, SubLevel::Ext("xhtml+xml".to_owned()), vec![])),
                    QualityItem::new(Mime(TopLevel::Application, SubLevel::Xml, vec![]), q(0.9)),
                    QualityItem::new(Mime(TopLevel::Star, SubLevel::Star, vec![]), q(0.8))],

            Context::Style
                => vec![qitem(Mime(TopLevel::Text, SubLevel::Css, vec![])),
                    QualityItem::new(Mime(TopLevel::Star, SubLevel::Star, vec![]), q(0.1))],
            _ => vec![qitem(Mime(TopLevel::Star, SubLevel::Star, vec![]))]
        };

        // Substep 2
        request.headers.set(Accept(value));
    }

    // Step 2
    if request.context != Context::Fetch && !request.headers.has::<AcceptLanguage>() {
        request.headers.set(AcceptLanguage(vec![qitem("en-US".parse().unwrap())]));
    }

    // TODO: Figure out what a Priority object is
    // Step 3
    // Step 4
    request.main_fetch(cors_flag)
}

/// [Main fetch](https://fetch.spec.whatwg.org/#concept-main-fetch)
fn main_fetch(Rc<RefCell<Request>>, _cors_flag: bool) -> Response {
    // TODO: Implement main fetch spec
    Response::network_error()
}

/// [Basic fetch](https://fetch.spec.whatwg.org#basic-fetch)
fn basic_fetch(Rc<RefCell<Request>>) -> Response {

    let scheme = request.url_list.last().unwrap().scheme.clone();

    match &*scheme {

        "about" => {
            let url = request.url_list.last().unwrap();
            match url.non_relative_scheme_data() {
                Some(s) if &*s == "blank" => {
                    let mut response = Response::new();
                    response.headers.set(ContentType(Mime(
                        TopLevel::Text, SubLevel::Html,
                        vec![(Attr::Charset, Value::Utf8)])));
                    response
                },
                _ => Response::network_error()
            }
        },

        "http" | "https" => {
            request.http_fetch(false, false, false)
        },

        "blob" | "data" | "file" | "ftp" => {
            // XXXManishearth handle these
            panic!("Unimplemented scheme for Fetch")
        },

        _ => Response::network_error()
    }
}

fn http_fetch_async(Rc<RefCell<Request>>,
                    cors_flag: bool,
                    cors_preflight_flag: bool,
                    authentication_fetch_flag: bool,
                    listener: Box<AsyncFetchListener + Send>) {

    spawn_named(format!("http_fetch for {:?}", request.get_last_url_string()), move || {
        let res = request.http_fetch(cors_flag, cors_preflight_flag,
                                  authentication_fetch_flag);
        listener.response_available(res);
    });
}

/// [HTTP fetch](https://fetch.spec.whatwg.org#http-fetch)
fn http_fetch(Rc<RefCell<Request>>,
              cors_flag: bool,
              cors_preflight_flag: bool,
              authentication_fetch_flag: bool) -> Response {

    // Step 1
    let mut response: Option<Rc<RefCell<Response>>> = None;

    // Step 2
    let mut actual_response: Option<Rc<RefCell<Response>>> = None;

    // Step 3
    if !request.skip_service_worker && !request.is_service_worker_global_scope {

        // TODO: Substep 1 (handle fetch unimplemented)
        if let Some(ref res) = response {
            let resp = res.borrow();

            // Substep 2
            actual_response = match resp.internal_response {
                Some(ref internal_res) => Some(internal_res.clone()),
                None => Some(res.clone())
            };

            // Substep 3
            if (resp.response_type == ResponseType::Opaque &&
                request.mode != RequestMode::NoCORS) ||
               (resp.response_type == ResponseType::OpaqueRedirect &&
                request.redirect_mode != RedirectMode::Manual) ||
               resp.response_type == ResponseType::Error {
                return Response::network_error();
            }
        }

        // Substep 4
        if let Some(ref res) = actual_response {
            let mut resp = res.borrow_mut();
            if resp.url_list.is_empty() {
                resp.url_list = request.url_list.clone();
            }
        }

        // Substep 5
        // TODO: set response's CSP list on actual_response
    }

    // Step 4
    if response.is_none() {

        // Substep 1
        if cors_preflight_flag {
            let mut method_mismatch = false;
            let mut header_mismatch = false;

            if let Some(ref mut cache) = request.cache {
                // FIXME: Once Url::Origin is available, rewrite origin to
                // take an Origin instead of a Url
                let origin = request.origin.clone().unwrap_or(Url::parse("").unwrap());
                let url = request.url_list.last().unwrap().clone();
                let credentials = request.credentials_mode == CredentialsMode::Include;
                let method_cache_match = cache.match_method(CacheRequestDetails {
                    origin: origin.clone(),
                    destination: url.clone(),
                    credentials: credentials
                }, request.method.clone());

                method_mismatch = !method_cache_match && (!is_simple_method(&request.method) ||
                    request.mode == RequestMode::ForcedPreflightMode);
                header_mismatch = request.headers.iter().any(|view|
                    !cache.match_header(CacheRequestDetails {
                        origin: origin.clone(),
                        destination: url.clone(),
                        credentials: credentials
                    }, view.name()) && !is_simple_header(&view)
                    );
            }

            if method_mismatch || header_mismatch {
                let preflight_result = request.preflight_fetch();
                if preflight_result.response_type == ResponseType::Error {
                    return Response::network_error();
                }
                response = Some(Rc::new(RefCell::new(preflight_result)));
            }
        }

        // Substep 2
        request.skip_service_worker = true;

        // Substep 3
        let credentials = match request.credentials_mode {
            CredentialsMode::Include => true,
            CredentialsMode::CredentialsSameOrigin if (!cors_flag ||
                request.response_tainting == ResponseTainting::Opaque)
                => true,
            _ => false
        };

        // Substep 4
        let fetch_result = http_network_or_cache_fetch(request, credentials, authentication_fetch_flag);

        // Substep 5
        if cors_flag && request.cors_check(&fetch_result).is_err() {
            return Response::network_error();
        }

        response = Some(Rc::new(RefCell::new(fetch_result)));
        actual_response = response.clone();
    }

    // Step 5
    let mut actual_response = Rc::try_unwrap(actual_response.unwrap()).ok().unwrap().into_inner();
    let mut response = Rc::try_unwrap(response.unwrap()).ok().unwrap();

    match actual_response.status.unwrap() {

        // Code 301, 302, 303, 307, 308
        StatusCode::MovedPermanently | StatusCode::Found | StatusCode::SeeOther |
        StatusCode::TemporaryRedirect | StatusCode::PermanentRedirect => {

            // Step 1
            if request.redirect_mode == RedirectMode::Error {
                return Response::network_error();
            }

            // Step 2-4
            if !actual_response.headers.has::<Location>() {
                return actual_response;
            }

            let location = match actual_response.headers.get::<Location>() {
                Some(&Location(ref location)) => location.clone(),
                _ => return Response::network_error(),
            };

            // Step 5
            let location_url = UrlParser::new().base_url(request.url_list.last().unwrap()).parse(&*location);

            // Step 6
            
            let location_url = match location_url {
                Ok(ref url) if url.scheme == "data" => { return Response::network_error(); }
                Ok(url) => url,
                _ => { return Response::network_error(); }
            };
            
            // Step 7
            if request.redirect_count == 20 {
                return Response::network_error();
            }
            
            // Step 8
            request.redirect_count += 1;

            match request.redirect_mode {
            
                // Step 9
                RedirectMode::Manual => {
                    *response.borrow_mut() = actual_response.to_filtered(ResponseType::Opaque);
                }

                // Step 10
                RedirectMode::Follow => {

                    // Substep 1
                    // FIXME: Use Url::origin
                    // if (request.mode == RequestMode::CORSMode || request.mode == RequestMode::ForcedPreflightMode) &&
                    //     location_url.origin() != request.url.origin() &&
                    //     has_credentials(&location_url) {
                    //     return Response::network_error();
                    // }

                    // Substep 2
                    if cors_flag && has_credentials(&location_url) {
                        return Response::network_error();
                    }

                    // Substep 3
                    // FIXME: Use Url::origin
                    // if cors_flag && location_url.origin() != request.url.origin() {
                    //     request.origin = Origin::UID(OpaqueOrigin);
                    // }

                    // Substep 4
                    if actual_response.status.unwrap() == StatusCode::SeeOther ||
                       ((actual_response.status.unwrap() == StatusCode::MovedPermanently ||
                         actual_response.status.unwrap() == StatusCode::Found) &&
                        request.method == Method::Post) {
                        request.method = Method::Get;
                    }

                    // Substep 5
                    request.url_list.push(location_url);

                    // Substep 6
                    return request.main_fetch(cors_flag);
                }
                RedirectMode::Error => { panic!("RedirectMode is Error after step 8") }
            }
        }

        // Code 401
        StatusCode::Unauthorized => {

            // Step 1
            // FIXME: Figure out what to do with request window objects
            if cors_flag {
                return response.into_inner();
            }

            // Step 2
            // TODO: Spec says requires testing on multiple WWW-Authenticate headers

            // Step 3
            if !request.use_url_credentials || authentication_fetch_flag {
                // TODO: Prompt the user for username and password from the window
            }

            // Step 4
            return request.http_fetch(cors_flag, cors_preflight_flag, true);
        }

        // Code 407
        StatusCode::ProxyAuthenticationRequired => {

            // Step 1
            // TODO: Figure out what to do with request window objects

            // Step 2
            // TODO: Spec says requires testing on Proxy-Authenticate headers

            // Step 3
            // TODO: Prompt the user for proxy authentication credentials

            // Step 4
            return request.http_fetch(cors_flag, cors_preflight_flag, authentication_fetch_flag);
        }

        _ => { }
    }

    let mut response = response.into_inner();

    // Step 6
    if authentication_fetch_flag {
        // TODO: Create authentication entry for this request
    }

    // Step 7
    response
}

/// [HTTP network or cache fetch](https://fetch.spec.whatwg.org#http-network-or-cache-fetch)
fn http_network_or_cache_fetch(request: Rc<RefCell<Request>>,
                               credentials_flag: bool,
                               authentication_fetch_flag: bool) -> Response {
    // TODO: Implement HTTP network or cache fetch spec

    // TODO: Implement Window enum for Request
    let request_has_no_window = true;

    // Step 1
    // TODO make an Rc<Request> with RefCell<> fields, or an Rc<RefCell<Request>>
    let mut self_copy;
    let httpRequest = if request_has_no_window && request.redirect_mode != RedirectMode::Follow {
        request
    } else {
        self_copy = request.clone();
        &mut self_copy
    }

    // Step 2
    let content_length_value = None;

    match httpRequest.body {
        // Step 3
        None => match request.method {
            Method::Head | Method::Post | Method::Put =>
                content_length_value = 0
        };
        // Step 4
        Some(t) => content_length_value = httpRequest.body.len()
    };

    // Step 5
    if let Some(content_length_value) = content_length_value {
        httpRequest.headers.set(ContentLength(content_length_value as u64));
    }

    // Step 6
    if httpRequest.referer == Referer::NoReferer {
        httpRequest.headers.set(Referer("".to_owned()));
    } else if httpRequest.referer == Referer::Client {
        // it should be impossible for referer to be Client during fetching
        // https://fetch.spec.whatwg.org/#concept-request-referrer
        unreachable!()
    } else
        httpRequest.headers.set(Referer(httpRequest.referer.serialize()));
    }

    // Step 7
    if httpRequest.omit_origin_header == false {
        // TODO update this when https://github.com/hyperium/hyper/pull/691 is finished
        httpRequest.headers.set_raw("origin", httpRequest.origin.serialize());
    }

    // Step 8
    if !httpRequest.headers.has::<UserAgent>() {
        httpRequest.headers.set(UserAgent(global_user_agent().to_owned()));
    }

    // Step 9
    if httpRequest.cache_mode == CacheMode::Default && is_no_store_cache(httpRequest.headers) {
        httpRequest.cache_mode = CacheMode::NoStore;
    }

    // Step 10
    modify_request_headers(httpRequest.headers);

    // Step 11
    // TODO some this step can't be implemented yet
    if credentials_flag {
        // Substep 1
        // TODO http://mxr.mozilla.org/servo/source/components/net/http_loader.rs#504

        // Substep 2
        let authorization_value = None;

        // Substep 3
        // TODO be able to retrieve https://fetch.spec.whatwg.org/#authentication-entry

        // Substep 4
        if authentication_fetch_flag {
            let current_url = httpRequest.current_url();
            if current_url.username.len() == 0 | !current_url.password.is_none() {
                // TODO spec needs to define how to convert this to an `Authorization` value
                authorization_value = current_url;
            }
        }

        // Substep 5
        if !authorization_value.is_none() {
            httpRequest.headers.set(Authorization(authorization_value);
        }
    }

    // Step 12
    // TODO this step can't be implemented

    // Step 13
    let mut response = None;

    // Step 14
    // TODO have a HTTP cache to check for a completed response
    let complete_http_response_from_cache = None;
    if httpRequest.cache_mode != CacheMode::NoStore && httpRequest.cache_mode != CacheMode::Reload &&
        !complete_http_response_from_cache.is_none() {

        // Substep 1
        if httpRequest.cache_mode == CacheMode::ForceCache {
            // TODO pull response from HTTP cache
            // response = httpRequest
        }

        let revalidation_needed = response_needs_revalidation(response);

        // Substep 2
        if !revalidation_needed && httpRequest.cache_mode == CacheMode::Default {
            // TODO pull response from HTTP cache
            // response = httpRequest
            response.cache_state = CacheState::Local;
        }

        // Substep 3
        if revalidation_needed && httpRequest.cache_mode == CacheMode::Default |
            httpRequest.cache_mode == CacheMode::NoCache {

            // TODO this substep
        }
    }

    // Step 15
    // TODO have a HTTP cache to check for a partial response
    if httpRequest.cache_mode == CacheMode::Default | httpRequest.cache_mode == CacheMode:ForceCache {
        // TODO this substep
    }

    // Step 16
    if response.is_none() {
        response = http_network_fetch(httpRequest, credentials);
    }

    // Step 17
    if response.status == StatusCode::NotModified &&
        (httpRequest.cache_mode == CacheMode::Default | httpRequest.cache_mode == CacheMode:NoCache) {

        // Substep 1
        // TODO this substep
        let cached_response = None;

        // Substep 2
        if cached_response == None {
            return Response::network_error();
        }

        // Substep 3

        // Substep 4
        // response = cached_response;

        // Substep 5
        // TODO have a cache state to update
        // response.cache_state == CacheState::Validated;
    }

    // Step 18
    response
}

/// [HTTP network fetch](https://fetch.spec.whatwg.org/#http-network-fetch)
fn http_network_fetch(&mut self, httpRequest: Request, credentials_flag: bool) -> Response {
    // TODO: Implement HTTP network fetch spec
    Response::network_error()
}

/// [CORS preflight fetch](https://fetch.spec.whatwg.org#cors-preflight-fetch)
fn preflight_fetch(&mut self) -> Response {
    // TODO: Implement preflight fetch spec
    Response::network_error()
}

/// [CORS check](https://fetch.spec.whatwg.org#concept-cors-check)
fn cors_check(&mut self, response: &Response) -> Result<(), ()> {
    // TODO: Implement CORS check spec
    Err(())
}

fn global_user_agent() -> String {
    // TODO have a better useragent string
    const user_agent_string: &'static str = "Servo";
    user_agent_string
}

fn has_credentials(url: &Url) -> bool {
    !url.username().unwrap_or("").is_empty() || url.password().is_some()
}

fn is_no_store_cache(headers: &Headers) -> bool {
    headers.has::<IfModifiedSince>() | headers.has::<IfNoneMatch>() |
    headers.has::<IfUnmodifiedSince>() | headers.has::<IfMatch>() |
    headers.has::<IfRange>()
}

fn is_simple_header(h: &HeaderView) -> bool {
    if h.is::<ContentType>() {
        match h.value() {
            Some(&ContentType(Mime(TopLevel::Text, SubLevel::Plain, _))) |
            Some(&ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, _))) |
            Some(&ContentType(Mime(TopLevel::Multipart, SubLevel::FormData, _))) => true,
            _ => false

        }
    } else {
        h.is::<Accept>() || h.is::<AcceptLanguage>() || h.is::<ContentLanguage>()
    }
}

fn is_simple_method(m: &Method) -> bool {
    match *m {
        Method::Get | Method::Head | Method::Post => true,
        _ => false
    }
}

fn response_needs_revalidation(response: &Response) -> bool {
    // TODO this function
    false
}

// fn modify_request_headers(headers: &mut Headers) -> {
//     // TODO this function

// }