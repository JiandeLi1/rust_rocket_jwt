use rocket::{
    get,
    routes,
    log::private::{log, Level::{Debug, Info, Error}},
    serde::{
    Serialize, Deserialize}, 
    request::{FromRequest, Outcome},
    http::Status,
};
//use rocket::serde::{Serialize, Deserialize};
use serde_json::{json, value};
use rocket::response::content;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};


const KEY: &[u8] = b"secret";

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate="rocket::serde")]
struct Claims {
    sub:String,
    company:String,
    exp:usize,
} 

struct Token;

impl Token {
    fn from_request(header: &str) -> Option<Token> {
        let split_vec = header.split_whitespace().collect::<Vec<_>>();
        if split_vec.len() !=2 {
            return None;
        }
         if split_vec[0] != "Bearer" {
            return None;
        }
        Self::from_jwt(split_vec[1])
    }

    fn from_jwt(token_string: &str) -> Option<Token> {
        let mut val = Validation::new(Algorithm::HS256);
        val.sub=Some("JD@JD.com".to_string());
        match decode::<Claims>(token_string, &DecodingKey::from_secret(KEY), &val){
            Ok(c)=>{
                log!(Error, "{:?}", c.claims);
                return Some(Token)
            },
            Err(_)=>None,
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token{
    type Error = ();
    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header= request.headers().get_one("Authorization");
        if let Some(header_auth) = auth_header{
            if let Some(auth) = Self::from_request(header_auth){
                return Outcome::Success(auth);
            }
        }
        Outcome::Failure((Status::Unauthorized,()))
    }
}



#[macro_use] extern crate rocket;
#[get("/val")]
async fn validation_jwt(_auth:Token) -> content::Json<&'static str>{
    log!(Info, "get_jwt!");
    let res=content::Json(r#"val"#);
    res
}

#[get("/get")]  
async fn get_jwt() -> content::Json<String>{
    let my_claims = Claims {
        sub:"JD@JD.com".to_string(),
        company:"JD".to_string(),
        exp:122222221123567,
    };
    let token = match encode(&Header::default(), &my_claims, &EncodingKey::from_secret(KEY)){
        Ok(c) => c,
        Err(_)=>panic!(),
    };
    let res:content::Json<String>=content::Json("{token:".to_string() + &token+"}");
    res
    
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rocket::build()
        .mount("/jwt", routes![get_jwt, validation_jwt])
        .launch()
        .await?;
    Ok(())
}
