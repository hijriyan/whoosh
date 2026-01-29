use crate::transformer::models::*;
use crate::transformer::registry::{
    parse_custom_request_transformers, parse_custom_response_transformers,
};
use http::{HeaderName, HeaderValue};
use std::str::FromStr;
use winnow::ascii::multispace0;
use winnow::combinator::{alt, delimited, preceded, separated};
use winnow::token::{literal as tag, take_until};
use winnow::{Parser, Result};

fn parse_quoted_str<'a>(input: &mut &'a str) -> Result<&'a str> {
    delimited('`', take_until(0.., '`'), '`').parse_next(input)
}

// --- Common Parsers (returning concrete types) ---

fn parse_replace_header_struct(input: &mut &str) -> Result<ReplaceHeader> {
    (
        tag("ReplaceHeader"),
        multispace0,
        delimited(
            '(',
            (
                parse_quoted_str,
                (multispace0, ',', multispace0),
                parse_quoted_str,
            ),
            ')',
        ),
    )
        .verify_map(|(_, _, (name, _, value))| {
            let name = HeaderName::from_str(name).ok()?;
            let value = HeaderValue::from_str(value).ok()?;
            Some(ReplaceHeader { name, value })
        })
        .parse_next(input)
}

fn parse_append_header_struct(input: &mut &str) -> Result<AppendHeader> {
    (
        tag("AppendHeader"),
        multispace0,
        delimited(
            '(',
            (
                parse_quoted_str,
                (multispace0, ',', multispace0),
                parse_quoted_str,
            ),
            ')',
        ),
    )
        .verify_map(|(_, _, (name, _, value))| {
            let name = HeaderName::from_str(name).ok()?;
            let value = HeaderValue::from_str(value).ok()?;
            Some(AppendHeader { name, value })
        })
        .parse_next(input)
}

fn parse_delete_header_struct(input: &mut &str) -> Result<DeleteHeader> {
    (
        tag("DeleteHeader"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .verify_map(|(_, _, name_str)| {
            let name = HeaderName::from_str(name_str).ok()?;
            Some(DeleteHeader { name })
        })
        .parse_next(input)
}

// --- Request Transformers ---

fn parse_replace_header_req(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    parse_replace_header_struct
        .map(|t| Box::new(t) as Box<dyn RequestTransformer>)
        .parse_next(input)
}

fn parse_append_header_req(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    parse_append_header_struct
        .map(|t| Box::new(t) as Box<dyn RequestTransformer>)
        .parse_next(input)
}

fn parse_delete_header_req(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    parse_delete_header_struct
        .map(|t| Box::new(t) as Box<dyn RequestTransformer>)
        .parse_next(input)
}

fn parse_replace_query(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    (
        tag("ReplaceQuery"),
        multispace0,
        delimited(
            '(',
            (
                parse_quoted_str,
                (multispace0, ',', multispace0),
                parse_quoted_str,
            ),
            ')',
        ),
    )
        .map(|(_, _, (key, _, value))| {
            Box::new(ReplaceQuery {
                key: key.to_string(),
                value: value.to_string(),
            }) as Box<dyn RequestTransformer>
        })
        .parse_next(input)
}

fn parse_append_query(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    (
        tag("AppendQuery"),
        multispace0,
        delimited(
            '(',
            (
                parse_quoted_str,
                (multispace0, ',', multispace0),
                parse_quoted_str,
            ),
            ')',
        ),
    )
        .map(|(_, _, (key, _, value))| {
            Box::new(AppendQuery {
                key: key.to_string(),
                value: value.to_string(),
            }) as Box<dyn RequestTransformer>
        })
        .parse_next(input)
}

fn parse_delete_query(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    (
        tag("DeleteQuery"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .map(|(_, _, key)| {
            Box::new(DeleteQuery {
                key: key.to_string(),
            }) as Box<dyn RequestTransformer>
        })
        .parse_next(input)
}

fn parse_request_transformer(input: &mut &str) -> Result<Box<dyn RequestTransformer>> {
    preceded(
        multispace0,
        alt((
            parse_replace_header_req,
            parse_append_header_req,
            parse_delete_header_req,
            parse_replace_query,
            parse_append_query,
            parse_delete_query,
            parse_custom_request_transformers,
        )),
    )
    .parse_next(input)
}

pub fn parse_transformers(input: &str) -> std::result::Result<Box<dyn RequestTransformer>, String> {
    let mut input_ref = input;
    let res: Result<Vec<Box<dyn RequestTransformer>>> =
        separated(1.., parse_request_transformer, preceded(multispace0, ';'))
            .parse_next(&mut input_ref);

    match res {
        Ok(transformers) => {
            if transformers.len() == 1 {
                Ok(transformers.into_iter().next().unwrap())
            } else {
                Ok(Box::new(ChainRequestTransformer { transformers }))
            }
        }
        Err(e) => Err(format!("Parse error: {}", e)),
    }
}

// --- Response Transformers ---

fn parse_replace_header_res(input: &mut &str) -> Result<Box<dyn ResponseTransformer>> {
    parse_replace_header_struct
        .map(|t| Box::new(t) as Box<dyn ResponseTransformer>)
        .parse_next(input)
}

fn parse_append_header_res(input: &mut &str) -> Result<Box<dyn ResponseTransformer>> {
    parse_append_header_struct
        .map(|t| Box::new(t) as Box<dyn ResponseTransformer>)
        .parse_next(input)
}

fn parse_delete_header_res(input: &mut &str) -> Result<Box<dyn ResponseTransformer>> {
    parse_delete_header_struct
        .map(|t| Box::new(t) as Box<dyn ResponseTransformer>)
        .parse_next(input)
}

fn parse_response_transformer(input: &mut &str) -> Result<Box<dyn ResponseTransformer>> {
    preceded(
        multispace0,
        alt((
            parse_replace_header_res,
            parse_append_header_res,
            parse_delete_header_res,
            parse_custom_response_transformers,
        )),
    )
    .parse_next(input)
}

pub fn parse_response_transformers(
    input: &str,
) -> std::result::Result<Box<dyn ResponseTransformer>, String> {
    let mut input_ref = input;
    let res: Result<Vec<Box<dyn ResponseTransformer>>> =
        separated(1.., parse_response_transformer, preceded(multispace0, ';'))
            .parse_next(&mut input_ref);

    match res {
        Ok(transformers) => {
            if transformers.len() == 1 {
                Ok(transformers.into_iter().next().unwrap())
            } else {
                Ok(Box::new(ChainResponseTransformer { transformers }))
            }
        }
        Err(e) => Err(format!("Parse error: {}", e)),
    }
}
