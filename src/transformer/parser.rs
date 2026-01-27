use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{char, multispace0},
    multi::separated_list1,
    sequence::preceded,
    IResult,
    Parser,
};
use crate::transformer::models::*;
use crate::transformer::registry::{parse_custom_request_transformers, parse_custom_response_transformers};
use http::{HeaderName, HeaderValue};
use std::str::FromStr;

fn parse_quoted_string(input: &str) -> IResult<&str, &str> {
    let (input, _) = char('`')(input)?;
    let (input, content) = take_until("`")(input)?;
    let (input, _) = char('`')(input)?;
    Ok((input, content))
}

// --- Common Parsers (returning concrete types) ---

fn parse_replace_header_struct(input: &str) -> IResult<&str, ReplaceHeader> {
    let (input, _) = tag("ReplaceHeader")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, name_str) = parse_quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value_str) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;

    let name = HeaderName::from_str(name_str).map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))?;
    let value = HeaderValue::from_str(value_str).map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))?;

    Ok((input, ReplaceHeader { name, value }))
}

fn parse_append_header_struct(input: &str) -> IResult<&str, AppendHeader> {
    let (input, _) = tag("AppendHeader")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, name_str) = parse_quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value_str) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;

    let name = HeaderName::from_str(name_str).map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))?;
    let value = HeaderValue::from_str(value_str).map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))?;

    Ok((input, AppendHeader { name, value }))
}

fn parse_delete_header_struct(input: &str) -> IResult<&str, DeleteHeader> {
    let (input, _) = tag("DeleteHeader")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, name_str) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;

    let name = HeaderName::from_str(name_str).map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))?;

    Ok((input, DeleteHeader { name }))
}

// --- Request Transformers ---

fn parse_replace_header_req(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, t) = parse_replace_header_struct(input)?;
    Ok((input, Box::new(t)))
}

fn parse_append_header_req(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, t) = parse_append_header_struct(input)?;
    Ok((input, Box::new(t)))
}

fn parse_delete_header_req(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, t) = parse_delete_header_struct(input)?;
    Ok((input, Box::new(t)))
}

fn parse_replace_query(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, _) = tag("ReplaceQuery")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, key) = parse_quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(ReplaceQuery { key: key.to_string(), value: value.to_string() })))
}

fn parse_append_query(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, _) = tag("AppendQuery")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, key) = parse_quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(AppendQuery { key: key.to_string(), value: value.to_string() })))
}

fn parse_delete_query(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, _) = tag("DeleteQuery")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, key) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(DeleteQuery { key: key.to_string() })))
}

fn parse_request_transformer(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
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
        ))
    ).parse(input)
}

pub fn parse_transformers(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let (input, transformers) = separated_list1(
        preceded(multispace0, char(';')),
        parse_request_transformer
    ).parse(input)?;

    if transformers.len() == 1 {
        Ok((input, transformers.into_iter().next().unwrap()))
    } else {
        Ok((input, Box::new(ChainRequestTransformer { transformers })))
    }
}

// --- Response Transformers ---

fn parse_replace_header_res(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
    let (input, t) = parse_replace_header_struct(input)?;
    Ok((input, Box::new(t)))
}

fn parse_append_header_res(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
    let (input, t) = parse_append_header_struct(input)?;
    Ok((input, Box::new(t)))
}

fn parse_delete_header_res(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
    let (input, t) = parse_delete_header_struct(input)?;
    Ok((input, Box::new(t)))
}

fn parse_response_transformer(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
    preceded(
        multispace0,
        alt((
            parse_replace_header_res,
            parse_append_header_res,
            parse_delete_header_res,
            parse_custom_response_transformers,
        ))
    ).parse(input)
}

pub fn parse_response_transformers(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
    let (input, transformers) = separated_list1(
        preceded(multispace0, char(';')),
        parse_response_transformer
    ).parse(input)?;

    if transformers.len() == 1 {
        Ok((input, transformers.into_iter().next().unwrap()))
    } else {
        Ok((input, Box::new(ChainResponseTransformer { transformers })))
    }
}
