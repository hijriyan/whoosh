use crate::router::matcher::*;
use crate::router::registry::parse_custom_rules;
use winnow::Parser;
use winnow::Result;
use winnow::ascii::multispace0;
use winnow::combinator::{alt, delimited, preceded, repeat};
use winnow::token::{literal as tag, take_until};

fn parse_quoted_str<'a>(input: &mut &'a str) -> Result<&'a str> {
    delimited('`', take_until(0.., '`'), '`').parse_next(input)
}

fn parse_host(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("Host"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .map(|(_, _, host)| {
            Box::new(HostMatcher {
                host: host.to_string(),
            }) as Box<dyn Matcher>
        })
        .parse_next(input)
}

fn parse_host_regexp(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("HostRegexp"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .verify_map(|(_, _, pattern)| {
            crate::router::matcher::compile_cached_regex(pattern)
                .ok()
                .map(|regex| {
                    Box::new(HostRegexpMatcher {
                        regex: (*regex).clone(),
                    }) as Box<dyn Matcher>
                })
        })
        .parse_next(input)
}

fn parse_path(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("Path"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .map(|(_, _, path)| {
            Box::new(PathMatcher {
                path: path.to_string(),
            }) as Box<dyn Matcher>
        })
        .parse_next(input)
}

fn parse_path_regexp(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("PathRegexp"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .verify_map(|(_, _, pattern)| {
            crate::router::matcher::compile_cached_regex(pattern)
                .ok()
                .map(|regex| {
                    Box::new(PathRegexpMatcher {
                        regex: (*regex).clone(),
                    }) as Box<dyn Matcher>
                })
        })
        .parse_next(input)
}

fn parse_path_prefix(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("PathPrefix"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .map(|(_, _, prefix)| {
            Box::new(PathPrefixMatcher {
                prefix: prefix.to_string(),
            }) as Box<dyn Matcher>
        })
        .parse_next(input)
}

fn parse_method(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("Method"),
        multispace0,
        delimited('(', parse_quoted_str, ')'),
    )
        .map(|(_, _, method)| {
            Box::new(MethodMatcher {
                method: method.to_string(),
            }) as Box<dyn Matcher>
        })
        .parse_next(input)
}

fn parse_header_regexp(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("HeaderRegexp"),
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
        .verify_map(|(_, _, (name, _, pattern))| {
            crate::router::matcher::compile_cached_regex(pattern)
                .ok()
                .map(|regex| {
                    Box::new(HeaderRegexpMatcher {
                        name: name.to_string(),
                        regex: (*regex).clone(),
                    }) as Box<dyn Matcher>
                })
        })
        .parse_next(input)
}

fn parse_query_regexp(input: &mut &str) -> Result<Box<dyn Matcher>> {
    (
        tag("QueryRegexp"),
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
        .verify_map(|(_, _, (key, _, pattern))| {
            crate::router::matcher::compile_cached_regex(pattern)
                .ok()
                .map(|regex| {
                    Box::new(QueryRegexpMatcher {
                        key: key.to_string(),
                        regex: (*regex).clone(),
                    }) as Box<dyn Matcher>
                })
        })
        .parse_next(input)
}

fn parse_not(input: &mut &str) -> Result<Box<dyn Matcher>> {
    preceded(('!', multispace0), parse_factor)
        .map(|matcher| Box::new(NotMatcher { matcher }) as Box<dyn Matcher>)
        .parse_next(input)
}

fn parse_factor(input: &mut &str) -> Result<Box<dyn Matcher>> {
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
        delimited('(', parse_expr, ')'),
    ))
    .parse_next(input)
}

fn parse_and(input: &mut &str) -> Result<Box<dyn Matcher>> {
    let first = parse_factor.parse_next(input)?;
    let mut matchers: Vec<_> = repeat(
        0..,
        preceded((multispace0, "&&", multispace0), parse_factor),
    )
    .parse_next(input)?;

    if matchers.is_empty() {
        Ok(first)
    } else {
        matchers.insert(0, first);
        Ok(Box::new(AndMatcher { matchers }))
    }
}

fn parse_or(input: &mut &str) -> Result<Box<dyn Matcher>> {
    let first = parse_and.parse_next(input)?;
    let mut matchers: Vec<_> =
        repeat(0.., preceded((multispace0, "||", multispace0), parse_and)).parse_next(input)?;

    if matchers.is_empty() {
        Ok(first)
    } else {
        matchers.insert(0, first);
        Ok(Box::new(OrMatcher { matchers }))
    }
}

fn parse_expr(input: &mut &str) -> Result<Box<dyn Matcher>> {
    parse_or.parse_next(input)
}

pub fn parse_rule(input: &str) -> Result<Box<dyn Matcher>, String> {
    let mut input_ref = input;
    match preceded(multispace0, parse_expr).parse_next(&mut input_ref) {
        Ok(matcher) => {
            if !input_ref.trim().is_empty() {
                return Err(format!("Unconsumed input: {}", input_ref));
            }
            Ok(matcher)
        }
        Err(e) => Err(format!("Parse error: {}", e)),
    }
}
