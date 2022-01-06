use std::collections::HashMap;
use std::iter;

use quote::quote;
use syn::parse::{Parse, ParseStream, Result};
use syn::spanned::Spanned;
use syn::{
    parse_quote, Error, Expr, FnArg, Ident, ImplItem, ImplItemMethod, ItemImpl,
    LitBool, Pat, Path, Token,
};

/// Ext. trait adding `partition_filter` to `Vec`. Would like to use `Vec::drain_filter`
/// but it's unstable for now.
pub trait VecPartitionFilterExt<Item> {
    fn partition_filter<F>(&mut self, predicate: F) -> Vec<Item>
    where
        F: FnMut(&mut Item) -> bool;
}

impl<Item> VecPartitionFilterExt<Item> for Vec<Item> {
    fn partition_filter<F>(&mut self, mut predicate: F) -> Vec<Item>
    where
        F: FnMut(&mut Item) -> bool,
    {
        let mut ret = Vec::new();
        let mut i = 0;
        while i != self.len() {
            if predicate(&mut self[i]) {
                ret.push(self.remove(i))
            } else {
                i += 1;
            }
        }
        ret
    }
}

mod kw {
    syn::custom_keyword!(shortcut);
    syn::custom_keyword!(rule);
    syn::custom_keyword!(parser);
}

struct MakeParserAttrs {
    parser: Path,
    rule_enum: Path,
}

struct AliasArgs {
    target: Ident,
    is_shortcut: bool,
}

struct PrecClimbArgs {
    child_rule: Ident,
    climber: Expr,
}

struct AliasSrc {
    ident: Ident,
    is_shortcut: bool,
}

struct ParsedFn<'a> {
    // Body of the function
    function: &'a mut ImplItemMethod,
    // Name of the function.
    fn_name: Ident,
    // Name of the first argument of the function, which should be of type `Node`.
    input_arg: Ident,
    // List of aliases pointing to this function
    alias_srcs: Vec<AliasSrc>,
}

impl Parse for MakeParserAttrs {
    fn parse(input: ParseStream) -> Result<Self> {
        // By default, the pest parser is the same type as the pest_consume one
        let mut parser = parse_quote!(Self);
        // By default, use the `Rule` type in scope
        let mut rule_enum = parse_quote!(Rule);

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::parser) {
                let _: kw::parser = input.parse()?;
                let _: Token![=] = input.parse()?;
                parser = input.parse()?;
            } else if lookahead.peek(kw::rule) {
                let _: kw::rule = input.parse()?;
                let _: Token![=] = input.parse()?;
                rule_enum = input.parse()?;
            } else {
                return Err(lookahead.error());
            }

            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            } else {
                break;
            }
        }

        Ok(MakeParserAttrs { parser, rule_enum })
    }
}

impl Parse for AliasArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let target = input.parse()?;
        let is_shortcut = if input.peek(Token![,]) {
            // #[alias(rule, shortcut = true)]
            let _: Token![,] = input.parse()?;
            let _: kw::shortcut = input.parse()?;
            let _: Token![=] = input.parse()?;
            let b: LitBool = input.parse()?;
            b.value
        } else {
            // #[alias(rule)]
            false
        };
        Ok(AliasArgs {
            target,
            is_shortcut,
        })
    }
}

impl Parse for PrecClimbArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let child_rule = input.parse()?;
        let _: Token![,] = input.parse()?;
        let climber = input.parse()?;
        Ok(PrecClimbArgs {
            child_rule,
            climber,
        })
    }
}

fn collect_aliases(
    imp: &mut ItemImpl,
) -> Result<HashMap<Ident, Vec<AliasSrc>>> {
    let functions = imp.items.iter_mut().flat_map(|item| match item {
        ImplItem::Method(m) => Some(m),
        _ => None,
    });

    let mut alias_map = HashMap::new();
    for function in functions {
        let fn_name = function.sig.ident.clone();
        let mut alias_attrs = function
            .attrs
            .partition_filter(|attr| attr.path.is_ident("alias"))
            .into_iter();

        if let Some(attr) = alias_attrs.next() {
            let args: AliasArgs = attr.parse_args()?;
            alias_map.entry(args.target).or_insert_with(Vec::new).push(
                AliasSrc {
                    ident: fn_name,
                    is_shortcut: args.is_shortcut,
                },
            );
        } else {
            // Self entry
            alias_map
                .entry(fn_name.clone())
                .or_insert_with(Vec::new)
                .push(AliasSrc {
                    ident: fn_name,
                    is_shortcut: false,
                });
        }
        if let Some(attr) = alias_attrs.next() {
            return Err(Error::new(
                attr.span(),
                "expected at most one alias attribute",
            ));
        }
    }

    Ok(alias_map)
}

fn extract_ident_argument(input_arg: &FnArg) -> Result<Ident> {
    match input_arg {
        FnArg::Receiver(_) => {
            return Err(Error::new(
                input_arg.span(),
                "this argument should not be `self`",
            ))
        }
        FnArg::Typed(input_arg) => match &*input_arg.pat {
            Pat::Ident(pat) => Ok(pat.ident.clone()),
            _ => {
                return Err(Error::new(
                    input_arg.span(),
                    "this argument should be a plain identifier instead of a pattern",
                ))
            }
        },
    }
}

fn parse_fn<'a>(
    function: &'a mut ImplItemMethod,
    alias_map: &mut HashMap<Ident, Vec<AliasSrc>>,
) -> Result<ParsedFn<'a>> {
    if function.sig.inputs.len() != 1 {
        return Err(Error::new(
            function.sig.inputs.span(),
            "A rule method must have 1 argument",
        ));
    }

    let fn_name = function.sig.ident.clone();
    // Get the name of the first function argument
    let input_arg = extract_ident_argument(&function.sig.inputs[0])?;
    let alias_srcs = alias_map.remove(&fn_name).unwrap_or_else(Vec::new);

    Ok(ParsedFn {
        function,
        fn_name,
        input_arg,
        alias_srcs,
    })
}

fn apply_prec_climb_attr(function: &mut ImplItemMethod) -> Result<()> {
    // `prec_climb` attrs
    let mut prec_climb_attrs: Vec<_> = function
        .attrs
        .partition_filter(|attr| attr.path.is_ident("prec_climb"));

    if prec_climb_attrs.is_empty() {
        return Ok(()); // do nothing
    } else if prec_climb_attrs.len() > 1 {
        return Err(Error::new(
            prec_climb_attrs[1].span(),
            "expected at most one prec_climb attribute",
        ));
    }

    let attr = prec_climb_attrs.pop().unwrap();
    let args = attr.parse_args()?;
    let PrecClimbArgs {
        child_rule,
        climber,
    } = args;

    if function.sig.inputs.len() != 3 {
        return Err(Error::new(
            function.sig.inputs.span(),
            "A prec_climb method must have 3 arguments",
        ));
    }

    // Create a new function that only has the middle argument of the original one.
    // It should have type Node and that way all the generic bits should work fine.
    let mut new_sig = function.sig.clone();
    let arg = &new_sig.inputs[1];
    let arg_name = extract_ident_argument(arg)?;
    new_sig.inputs = std::iter::once(arg.clone()).collect();

    let fn_name = &function.sig.ident;
    *function = parse_quote!(
        #new_sig {
            #function

            #arg_name
                .into_children()
                .prec_climb(
                    &*#climber,
                    Self::#child_rule,
                    #fn_name,
                )
        }
    );

    Ok(())
}

fn apply_special_attrs(f: &mut ParsedFn, rule_enum: &Path) -> Result<()> {
    let function = &mut *f.function;
    let fn_name = &f.fn_name;
    let input_arg = &f.input_arg;

    // `alias` attr
    // f.alias_srcs has always at least 1 element because it has an entry pointing from itself.
    let aliases = f
        .alias_srcs
        .iter()
        .map(|src| &src.ident)
        .filter(|i| i != &fn_name);
    let block = &function.block;
    let self_ty = quote!(<Self as ::pest_consume::Parser>);
    function.block = parse_quote!({
        let mut #input_arg = #input_arg;
        // While the current rule allows shortcutting, and there is a single child, and the
        // child can still be parsed by the current function, then skip to that child.
        while #self_ty::allows_shortcut(#input_arg.as_rule()) {
            if let ::std::result::Result::Ok(child)
                    = #input_arg.children().single() {
                if child.as_aliased_rule::<Self>() == #self_ty::rule_alias(#rule_enum::#fn_name) {
                    #input_arg = child;
                    continue;
                }
            }
            break
        }

        match #input_arg.as_rule() {
            #(#rule_enum::#aliases => Self::#aliases(#input_arg),)*
            #rule_enum::#fn_name => #block,
            r => panic!(
                "pest_consume::parser: called the `{}` method on a node with rule `{:?}`",
                stringify!(#fn_name),
                r
            )
        }
    });

    Ok(())
}

pub fn make_parser(
    attrs: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> Result<proc_macro2::TokenStream> {
    let attrs: MakeParserAttrs = syn::parse(attrs)?;
    let parser = &attrs.parser;
    let rule_enum = &attrs.rule_enum;
    let mut imp: ItemImpl = syn::parse(input)?;

    let mut alias_map = collect_aliases(&mut imp)?;
    let rule_alias_branches: Vec<_> = alias_map
        .iter()
        .flat_map(|(tgt, srcs)| iter::repeat(tgt).zip(srcs))
        .map(|(tgt, src)| {
            let ident = &src.ident;
            quote!(
                #rule_enum::#ident => Self::AliasedRule::#tgt,
            )
        })
        .collect();
    let aliased_rule_variants: Vec<_> =
        alias_map.iter().map(|(tgt, _)| tgt.clone()).collect();
    let shortcut_branches: Vec<_> = alias_map
        .iter()
        .flat_map(|(_tgt, srcs)| srcs)
        .map(|AliasSrc { ident, is_shortcut }| {
            quote!(
                #rule_enum::#ident => #is_shortcut,
            )
        })
        .collect();

    let fn_map: HashMap<Ident, ParsedFn> = imp
        .items
        .iter_mut()
        .flat_map(|item| match item {
            ImplItem::Method(m) => Some(m),
            _ => None,
        })
        .map(|method| {
            *method = parse_quote!(
                #[allow(non_snake_case)]
                #method
            );
            apply_prec_climb_attr(method)?;
            let mut f = parse_fn(method, &mut alias_map)?;
            apply_special_attrs(&mut f, &rule_enum)?;
            Ok((f.fn_name.clone(), f))
        })
        .collect::<Result<_>>()?;

    // Entries that remain in the alias map don't have a matching method, so we create one.
    let extra_fns: Vec<_> = alias_map
        .iter()
        .map(|(tgt, srcs)| {
            // Get the signature of one of the functions that has this alias. They should all have
            // essentially the same signature anyways.
            let f = fn_map.get(&srcs.first().unwrap().ident).unwrap();
            let input_arg = f.input_arg.clone();
            let mut sig = f.function.sig.clone();
            sig.ident = tgt.clone();
            let srcs = srcs.iter().map(|src| &src.ident);

            Ok(parse_quote!(
                #sig {
                    match #input_arg.as_rule() {
                        #(#rule_enum::#srcs => Self::#srcs(#input_arg),)*
                        // We can't match on #rule_enum::#tgt since `tgt` might be an arbitrary
                        // identifier.
                        r if &format!("{:?}", r) == stringify!(#tgt) =>
                            return ::std::result::Result::Err(#input_arg.error(format!(
                                "pest_consume::parser: missing method for rule {}",
                                stringify!(#tgt),
                            ))),
                        r => return ::std::result::Result::Err(#input_arg.error(format!(
                            "pest_consume::parser: called method `{}` on a node with rule `{:?}`",
                            stringify!(#tgt),
                            r
                        ))),
                    }
                }
            ))
        })
        .collect::<Result<_>>()?;
    imp.items.extend(extra_fns);

    let ty = &imp.self_ty;
    let (impl_generics, _, where_clause) = imp.generics.split_for_impl();
    Ok(quote!(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[allow(non_camel_case_types)]
        pub enum AliasedRule {
            #(#aliased_rule_variants,)*
        }

        impl #impl_generics ::pest_consume::Parser for #ty #where_clause {
            type Rule = #rule_enum;
            type AliasedRule = AliasedRule;
            type Parser = #parser;
            fn rule_alias(rule: Self::Rule) -> Self::AliasedRule {
                match rule {
                    #(#rule_alias_branches)*
                    // TODO: return a proper error ?
                    r => panic!("Rule `{:?}` does not have a corresponding parsing method", r),
                }
            }
            fn allows_shortcut(rule: Self::Rule) -> bool {
                match rule {
                    #(#shortcut_branches)*
                    _ => false,
                }
            }
        }

        #imp
    ))
}
