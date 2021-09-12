use actix_web::HttpResponse;
use actix_web::web;
use actix_web::http::header::{LOCATION};

#[derive(serde::Deserialize)]
pub struct FormData {
    username: String,
    password: String,
}

pub async fn submit_login(_form: web::Form<FormData>) -> HttpResponse {
    HttpResponse::SeeOther().insert_header((LOCATION, "/")).finish()
}
