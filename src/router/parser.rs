use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{char, multispace0},
    multi::many0,
    sequence::{delimited, preceded},
    IResult,
    Parser,
};
use crate::router::matcher::*;
use crate::router::registry::{parse_custom_rules, register_hosts};

fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    let (input, _) = char('`')(input)?;
    let (input, content) = take_until("`")(input)?;
    let (input, _) = char('`')(input)?;
    Ok((input, content.to_string()))
}

fn parse_host(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("Host")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, host) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    register_hosts(vec![host.clone()]);
    Ok((input, Box::new(HostMatcher { host })))
}

fn parse_host_regexp(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("HostRegexp")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, pattern) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    
    match crate::router::matcher::compile_cached_regex(&pattern) {
        Ok(regex) => Ok((input, Box::new(HostRegexpMatcher { regex: (*regex).clone() }))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }
}

fn parse_path(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("Path")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, path) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(PathMatcher { path })))
}

fn parse_path_regexp(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("PathRegexp")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, pattern) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    
    match crate::router::matcher::compile_cached_regex(&pattern) {
        Ok(regex) => Ok((input, Box::new(PathRegexpMatcher { regex: (*regex).clone() }))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }
}

fn parse_path_prefix(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("PathPrefix")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, prefix) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(PathPrefixMatcher { prefix })))
}

fn parse_method(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("Method")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, method) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(MethodMatcher { method })))
}

fn parse_header_regexp(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("HeaderRegexp")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, name) = parse_quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, pattern) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;

    match crate::router::matcher::compile_cached_regex(&pattern) {
        Ok(regex) => Ok((input, Box::new(HeaderRegexpMatcher { name, regex: (*regex).clone() }))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }
}

fn parse_query_regexp(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("QueryRegexp")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, key) = parse_quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, pattern) = parse_quoted_string(input)?;
    let (input, _) = char(')')(input)?;

    match crate::router::matcher::compile_cached_regex(&pattern) {
        Ok(regex) => Ok((input, Box::new(QueryRegexpMatcher { key, regex: (*regex).clone() }))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }
}

fn parse_not(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = char('!')(input)?;
    let (input, _) = multispace0(input)?;
    let (input, matcher) = parse_factor(input)?;
    Ok((input, Box::new(NotMatcher { matcher })))
}

fn parse_factor(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    preceded(
        multispace0,
        alt((
            parse_not,
            parse_host_regexp,
            parse_host,
            parse_path_prefix,
            parse_path_regexp,
            parse_path,
            parse_method,
            parse_header_regexp,
            parse_query_regexp,
            parse_custom_rules,
            delimited(
                char('('),
                parse_expr,
                char(')'),
            )
        ))
    ).parse(input)
}

fn parse_and(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, left) = parse_factor(input)?;
    let (input, rights) = many0(
        preceded(
            (multispace0, tag("&&"), multispace0),
            parse_factor
        )
    ).parse(input)?;

    let result = rights.into_iter().fold(left, |acc, right| {
        Box::new(AndMatcher { left: acc, right })
    });

    Ok((input, result))
}

fn parse_or(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, left) = parse_and(input)?;
    let (input, rights) = many0(
        preceded(
            (multispace0, tag("||"), multispace0),
            parse_and
        )
    ).parse(input)?;

    let result = rights.into_iter().fold(left, |acc, right| {
        Box::new(OrMatcher { left: acc, right })
    });

    Ok((input, result))
}

fn parse_expr(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    parse_or(input)
}

pub fn parse_rule(input: &str) -> Result<Box<dyn Matcher>, String> {
    match parse_expr(input) {
        Ok((remaining, matcher)) => {
            if !remaining.trim().is_empty() {
                return Err(format!("Unconsumed input: {}", remaining));
            }
            Ok(matcher)
        },
        Err(e) => Err(format!("Parse error: {}", e)),
    }
}
