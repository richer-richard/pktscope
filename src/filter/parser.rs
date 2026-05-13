use nom::{
    IResult,
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, multispace0, none_of},
    combinator::{map, recognize, value},
    multi::{many0, many1},
    sequence::{delimited, preceded, tuple},
};

use super::ast::*;

pub fn parse_filter(input: &str) -> Result<FilterExpr, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("empty filter".into());
    }
    match expr(input) {
        Ok(("", expr)) => Ok(expr),
        Ok((rest, _)) => Err(format!("unexpected trailing input: '{}'", rest)),
        Err(e) => Err(format!("parse error: {}", e)),
    }
}

fn ws<'a, F, O>(f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(multispace0, f, multispace0)
}

fn expr(input: &str) -> IResult<&str, FilterExpr> {
    let (input, first) = and_term(input)?;
    let (input, rest) = many0(preceded(ws(alt((tag("||"), tag("or")))), and_term))(input)?;

    let result = rest.into_iter().fold(first, |acc, term| {
        FilterExpr::Or(Box::new(acc), Box::new(term))
    });
    Ok((input, result))
}

fn and_term(input: &str) -> IResult<&str, FilterExpr> {
    let (input, first) = unary(input)?;
    let (input, rest) = many0(preceded(ws(alt((tag("&&"), tag("and")))), unary))(input)?;

    let result = rest.into_iter().fold(first, |acc, term| {
        FilterExpr::And(Box::new(acc), Box::new(term))
    });
    Ok((input, result))
}

fn unary(input: &str) -> IResult<&str, FilterExpr> {
    alt((
        map(preceded(ws(alt((tag("not"), tag("!")))), unary), |e| {
            FilterExpr::Not(Box::new(e))
        }),
        atom,
    ))(input)
}

fn atom(input: &str) -> IResult<&str, FilterExpr> {
    alt((
        delimited(ws(char('(')), expr, ws(char(')'))),
        contains_expr,
        comparison_expr,
        map(ws(protocol_atom), FilterExpr::ProtocolPresent),
    ))(input)
}

fn contains_expr(input: &str) -> IResult<&str, FilterExpr> {
    let (input, field) = ws(field_path)(input)?;
    let (input, _) = ws(tag("contains"))(input)?;
    let (input, pattern) = ws(word)(input)?;

    Ok((
        input,
        FilterExpr::Contains {
            field,
            pattern: pattern.to_string(),
        },
    ))
}

fn comparison_expr(input: &str) -> IResult<&str, FilterExpr> {
    let (input, field) = ws(field_path)(input)?;
    let (input, op) = ws(compare_op)(input)?;
    let (input, val) = ws(filter_value)(input)?;

    Ok((
        input,
        FilterExpr::Comparison {
            field,
            op,
            value: val,
        },
    ))
}

fn field_path(input: &str) -> IResult<&str, FieldPath> {
    let (input, first) = identifier(input)?;
    let (input, rest) = many0(preceded(char('.'), identifier))(input)?;

    let mut segments = vec![first.to_string()];
    for s in rest {
        segments.push(s.to_string());
    }

    // Only accept if there's at least a dot (it's a field, not a bare protocol)
    if segments.len() < 2 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    Ok((input, FieldPath { segments }))
}

fn identifier(input: &str) -> IResult<&str, &str> {
    recognize(many1(alt((
        nom::character::complete::alphanumeric1,
        recognize(char('_')),
    ))))(input)
}

fn word(input: &str) -> IResult<&str, &str> {
    recognize(many1(none_of(" \t\n\r)")))(input)
}

fn compare_op(input: &str) -> IResult<&str, CompareOp> {
    alt((
        value(CompareOp::Ne, tag("!=")),
        value(CompareOp::Eq, tag("==")),
    ))(input)
}

fn filter_value(input: &str) -> IResult<&str, FilterValue> {
    alt((ip_addr_value, integer_value, string_value))(input)
}

fn ip_addr_value(input: &str) -> IResult<&str, FilterValue> {
    let (remaining, addr_str) = recognize(tuple((
        nom::character::complete::digit1,
        char('.'),
        nom::character::complete::digit1,
        char('.'),
        nom::character::complete::digit1,
        char('.'),
        nom::character::complete::digit1,
    )))(input)?;

    match addr_str.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => Ok((remaining, FilterValue::IpAddr(std::net::IpAddr::V4(addr)))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

fn integer_value(input: &str) -> IResult<&str, FilterValue> {
    let (remaining, digits) = nom::character::complete::digit1(input)?;
    match digits.parse::<i64>() {
        Ok(n) => Ok((remaining, FilterValue::Integer(n))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Digit,
        ))),
    }
}

fn string_value(input: &str) -> IResult<&str, FilterValue> {
    let (remaining, w) = word(input)?;
    Ok((remaining, FilterValue::Str(w.to_string())))
}

fn protocol_atom(input: &str) -> IResult<&str, ProtocolAtom> {
    // Order matters: longer matches first
    alt((
        value(ProtocolAtom::Icmpv6, tag("icmpv6")),
        value(ProtocolAtom::Icmp, tag("icmp")),
        value(ProtocolAtom::Ipv6, tag("ipv6")),
        value(ProtocolAtom::Ipv4, tag("ipv4")),
        value(ProtocolAtom::Ethernet, tag("eth")),
        value(ProtocolAtom::Tcp, tag("tcp")),
        value(ProtocolAtom::Udp, tag("udp")),
        value(ProtocolAtom::Arp, tag("arp")),
        value(ProtocolAtom::Dns, tag("dns")),
        value(ProtocolAtom::Tls, tag("tls")),
        value(ProtocolAtom::Ip, tag("ip")),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_parse_protocol_atom() {
        assert_eq!(
            parse_filter("tcp").unwrap(),
            FilterExpr::ProtocolPresent(ProtocolAtom::Tcp)
        );
        assert_eq!(
            parse_filter("dns").unwrap(),
            FilterExpr::ProtocolPresent(ProtocolAtom::Dns)
        );
    }

    #[test]
    fn test_parse_comparison() {
        let expr = parse_filter("tcp.port == 80").unwrap();
        match expr {
            FilterExpr::Comparison { field, op, value } => {
                assert_eq!(field.as_str(), "tcp.port");
                assert_eq!(op, CompareOp::Eq);
                assert_eq!(value, FilterValue::Integer(80));
            }
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn test_parse_ip_comparison() {
        let expr = parse_filter("ip.src == 10.0.0.1").unwrap();
        match expr {
            FilterExpr::Comparison { field, op, value } => {
                assert_eq!(field.as_str(), "ip.src");
                assert_eq!(op, CompareOp::Eq);
                assert_eq!(
                    value,
                    FilterValue::IpAddr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                );
            }
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn test_parse_contains() {
        let expr = parse_filter("tls.sni contains example.com").unwrap();
        match expr {
            FilterExpr::Contains { field, pattern } => {
                assert_eq!(field.as_str(), "tls.sni");
                assert_eq!(pattern, "example.com");
            }
            _ => panic!("Expected contains"),
        }
    }

    #[test]
    fn test_parse_and() {
        let expr = parse_filter("tcp and ip.src == 10.0.0.1").unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));
    }

    #[test]
    fn test_parse_or() {
        let expr = parse_filter("tcp || udp").unwrap();
        assert!(matches!(expr, FilterExpr::Or(_, _)));
    }

    #[test]
    fn test_parse_not() {
        let expr = parse_filter("not tcp").unwrap();
        assert!(matches!(expr, FilterExpr::Not(_)));

        let expr2 = parse_filter("!udp").unwrap();
        assert!(matches!(expr2, FilterExpr::Not(_)));
    }

    #[test]
    fn test_parse_parentheses() {
        let expr = parse_filter("(tcp || udp) && ip.src == 10.0.0.1").unwrap();
        assert!(matches!(expr, FilterExpr::And(_, _)));
    }

    #[test]
    fn test_parse_precedence() {
        // AND binds tighter than OR
        let expr = parse_filter("tcp || udp && arp").unwrap();
        // Should be: tcp || (udp && arp)
        match expr {
            FilterExpr::Or(left, right) => {
                assert!(matches!(
                    *left,
                    FilterExpr::ProtocolPresent(ProtocolAtom::Tcp)
                ));
                assert!(matches!(*right, FilterExpr::And(_, _)));
            }
            _ => panic!("Expected OR at top level"),
        }
    }

    #[test]
    fn test_parse_ne() {
        let expr = parse_filter("tcp.port != 80").unwrap();
        match expr {
            FilterExpr::Comparison { op, .. } => assert_eq!(op, CompareOp::Ne),
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_filter("").is_err());
    }

    #[test]
    fn test_dns_qname_contains() {
        let expr = parse_filter("dns.qname contains google").unwrap();
        match expr {
            FilterExpr::Contains { field, pattern } => {
                assert_eq!(field.as_str(), "dns.qname");
                assert_eq!(pattern, "google");
            }
            _ => panic!("Expected contains"),
        }
    }
}
