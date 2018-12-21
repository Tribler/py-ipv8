from xml.etree import ElementTree as ET

from six.moves import StringIO

from .opcodereader import pretty_str_simple_lambda
from ..validation.types import JSONType, OptionalKey, TUPLE_TYPE


INDENT_SEP = "&nbsp;"
INDENT_STR = INDENT_SEP * 4
COLORS = {
    "GET": ("DodgerBlue", "lightblue"),
    "HEAD": ("green", "PaleGreen"),
    "POST": ("Crimson", "LightCoral"),
    "PUT": ("DarkOrange", "Wheat"),
    "DELETE": ("HotPink", "LightPink"),
    "PATCH": ("Gold", "LightGoldenRodYellow")
}


def create_new_document():
    html = ET.Element("html")
    css = ET.Element("style")
    css.text = ":root { --method-color: #333; --method-highlight: #EEE}"
    css.text += "tr.code:nth-child(even) {background: #CCC}"
    css.text += "tr.code:nth-child(odd) {background: #FFF}"
    css.text += "table { border-spacing: 0; border-collapse: collapse;}"
    css.text += "div.precondition { background-color: var(--method-highlight); padding: 15px;"
    css.text += "border-left: 12px solid var(--method-color);}"
    css.text += "div.group { outline: 2px solid black; background-color: white;}"
    css.text += "span.group { outline: 2px solid black; background-color: white;}"
    css.text += "div.header { width: 100%; position: relative; margin-left: -10px; height: 100px; margin-top: 0px;"
    css.text += "margin-bottom: 20px; background-color: #EEE; border-left: 20px solid var(--method-color);}"
    css.text += "div.title { width: 100%; position: relative; margin-left: -10px; margin-top: 0px;"
    css.text += "margin-bottom: 20px; background-color: #EEE; border-left: 20px solid #333;}"
    css.text += "p { padding: 15px;}"
    css.text += "td.code { padding-right: 10px; padding-left: 3px;}"
    html.append(css)
    body = ET.Element("body")
    html.append(body)
    return html, body


def document_to_string(document):
    stream = StringIO()
    ET.ElementTree(document).write(stream, encoding="utf8", method="html")
    return stream.getvalue()


def python_struct_to_str(data):
    if isinstance(data, dict):
        return '{', '}', data
    if isinstance(data, (list, TUPLE_TYPE)):
        return '[', ']', (data if isinstance(data, list) else list(data.inner_types))
    if isinstance(data, JSONType):
        return data.json_type, None, None
    return data, None, None


def add_br_if_needed(code_element, annotation_element):
    for element in [code_element, annotation_element]:
        truetype = ET.Element("tt")
        truetype.text = "&zwnj;"
        child = ET.Element("td")
        child.set("class", "code")
        child.append(truetype)
        rowelem = ET.Element("tr", {"class": "code"})
        rowelem.append(child)
        element.append(rowelem)


def get_last_child(element):
    children = list(element)
    if children:
        return get_last_child(children[-1])
    return element


def create_color_profile(primary, secondary):
    return "--method-color: %s; --method-highlight: %s" % (primary, secondary)


def create_restinput_spec(pattern, code_element, annotation_element, indent=""):
    # Generate prefixes and postfixes
    if isinstance(pattern, tuple):
        prefix, postfix, remainder = python_struct_to_str(pattern[0])
        prefixes = (prefix, pattern[1])
    else:
        prefix, postfix, remainder = python_struct_to_str(pattern)
        prefixes = (prefix, "")
    # Insert prefix
    add_br_if_needed(code_element, annotation_element)
    get_last_child(code_element).text += indent + prefixes[0]
    get_last_child(annotation_element).text += prefixes[1]
    # Insert content
    if isinstance(remainder, list):
        for element in remainder:
            create_restinput_spec(element, code_element, annotation_element, indent + INDENT_STR)
    elif isinstance(remainder, dict):
        if all(isinstance(k, (str, OptionalKey)) for k in remainder.keys()):
            ordered_items = [(k, v) for k, v in remainder.items() if not isinstance(k, OptionalKey)] +\
                            [(k, v) for k, v in remainder.items() if isinstance(k, OptionalKey)]
            for k, v in ordered_items:
                add_br_if_needed(code_element, annotation_element)
                if isinstance(k, OptionalKey):
                    last_child = get_last_child(code_element)
                    italic_lable = ET.Element("i")
                    italic_lable.text = last_child.text
                    last_child.text = ""
                    last_child.append(italic_lable)
                get_last_child(code_element).text += "%s\"%s\":" % (indent + INDENT_STR, k)
                create_restinput_spec(v, code_element, annotation_element, indent + INDENT_STR * 2)
        elif len(remainder.keys()) == 1:
            match_key = list(remainder.keys())[0]
            create_restinput_spec(match_key, code_element, annotation_element, indent + INDENT_STR)
            get_last_child(code_element).text += ":"
            create_restinput_spec(remainder[match_key], code_element, annotation_element, indent + INDENT_STR * 2)
        else:
            raise RuntimeError("Illegal pattern specification, more than one dynamic pattern in dict keys %s" %
                               str(remainder.keys()))
    # Insert postfix
    if postfix:
        add_br_if_needed(code_element, annotation_element)
        get_last_child(code_element).text += indent + postfix


def create_pattern_table(pattern):
    table = ET.Element("table", {"style": "tr: {background: #CCC}"})
    # First (header) row
    table_tr1 = ET.Element("tr")
    table_tr1_th1 = ET.Element("th", {"align": "left", "style": "padding-left: 4px; padding-right: 30px"})
    table_tr1_th1.text = "Pattern"
    table_tr1.append(table_tr1_th1)
    table_tr1_th2 = ET.Element("th", {"align": "left", "style": "padding-left: 4px"})
    table_tr1_th2.text = "Annotations"
    table_tr1.append(table_tr1_th2)
    table.append(table_tr1)
    # Second (content) row
    table_tr2 = ET.Element("tr", {"style": "background: #000; padding-right: 10px"})
    table_tr2_td1 = ET.Element("td")
    code_element = ET.Element("table", {"width": "100%"})
    table_tr2_td1.append(code_element)
    table_tr2.append(table_tr2_td1)
    table_tr2_td2 = ET.Element("td")
    annotation_element = ET.Element("table", {"width": "100%"})
    table_tr2_td2.append(annotation_element)
    table_tr2.append(table_tr2_td2)
    table.append(table_tr2)
    # Fill
    create_restinput_spec(pattern, code_element, annotation_element)
    return table


def create_postcondition_descriptor(spec, pattern, colors):
    response_code, conditional_lambda = spec
    container = ET.Element("div", {"class": "group"})
    # Rule
    rule_div = ET.Element("div", {"class": "precondition", "style": colors})
    rcode_label = ET.Element("b")
    rcode_label.text = "Return code%s: " % ("s" if isinstance(response_code, list) else "")
    rcode_label.tail = ", ".join([str(code) for code in response_code]) if isinstance(response_code, list)\
        else str(response_code)
    rule_div.append(rcode_label)
    pretty_precondition = pretty_str_simple_lambda(conditional_lambda)
    if pretty_precondition != "True":
        rule_div.append(ET.Element("br"))
        precondition_label = ET.Element("b")
        precondition_label.text = "Precondition: "
        precondition_label.tail = pretty_precondition
        rule_div.append(precondition_label)
    container.append(rule_div)
    table_container = ET.Element("p")
    table_container.append(create_pattern_table(pattern))
    container.append(table_container)
    return container


def create_precondition_descriptor(option, pattern, colors):
    container = ET.Element("div", {"style": "%s; border-left: 2px solid var(--method-color); padding-left: 15px" %
                                   colors})
    argument_label = ET.Element("b", {"style": "margin-left: 5px"})
    argument_label.text = "Argument: "
    argument_label.tail = option
    container.append(argument_label)
    table_span = ET.Element("div", {"style": "margin-top: 2px; margin-bottom: 10px"})
    table_span.append(create_pattern_table(pattern))
    container.append(table_span)
    return container


def create_document_from_apis(restapis, title, subtitle, introduction):
    html, body = create_new_document()

    # Title
    body_title = ET.Element("div", {"class": "title"})
    body_title_text = ET.Element("h1", {"style": "margin-bottom: 0px;"})
    body_title_text.text = title
    body_title.append(body_title_text)
    # Subtitle
    subtitle_table = ET.Element("table")
    subtitle_table_tr1 = ET.Element("tr")
    subtitle_table_tr1_td1 = ET.Element("td")
    subtitle_text = ET.Element("b")
    subtitle_text.text = "Endpoint address: "
    subtitle_table_tr1_td1.append(subtitle_text)
    subtitle_table_tr1.append(subtitle_table_tr1_td1)
    subtitle_table_tr1_td2 = ET.Element("td", {"style": "padding-left: 20px"})
    subtitle_table_tr1_td2.text = subtitle
    subtitle_table_tr1.append(subtitle_table_tr1_td2)
    subtitle_table.append(subtitle_table_tr1)
    subtitle_table_tr2 = ET.Element("tr")
    subtitle_table_tr2_td1 = ET.Element("td")
    methods_text = ET.Element("b")
    methods_text.text = "Available methods: "
    subtitle_table_tr2_td1.append(methods_text)
    subtitle_table_tr2.append(subtitle_table_tr2_td1)
    subtitle_table_tr2_td2 = ET.Element("td", {"style": "padding-left: 20px"})
    subtitle_table_tr2_td2.text = ", ".join(list(restapis.keys()))
    subtitle_table_tr2.append(subtitle_table_tr2_td2)
    subtitle_table.append(subtitle_table_tr2)
    body_title.append(subtitle_table)
    # Introduction
    body_title_desc = ET.Element("p")
    body_title_desc.text = introduction
    body_title.append(body_title_desc)
    body.append(body_title)

    # Methods
    for method in sorted(restapis.keys()):
        colors = create_color_profile(*COLORS.get(method, create_color_profile("#333", "#EEE")))
        method_title = ET.Element("div", {"class": "header", "align": "center",
                                          "style": "%s; display: table;" % colors})
        method_title_text = ET.Element("h2", {"align": "left", "style": "display: table-cell; vertical-align: middle;"})
        method_title_text.text = "HTTP METHOD: " + method
        method_title.append(method_title_text)
        body.append(method_title)

        if restapis[method][1]:
            method_description = ET.Element("pre")
            method_description.text = restapis[method][1]
            body.append(method_description)

        inputs_title = ET.Element("h3")
        inputs_title.text = "Arguments"
        body.append(inputs_title)

        for api in restapis[method][0]:
            for option, pattern in api["preconditions"].items():
                body.append(create_precondition_descriptor(option, pattern, colors))
            if not api["preconditions"].items():
                noargs_div = ET.Element("div")
                noargs = ET.Element("i")
                noargs.text = "This endpoint method takes no arguments."
                noargs_div.append(noargs)
                body.append(noargs_div)

        outputs_title = ET.Element("h3")
        outputs_title.text = "Output"
        body.append(outputs_title)
        for api in restapis[method][0]:
            for spec, pattern in api["postconditions"].items():
                body.append(create_postcondition_descriptor(spec, pattern, colors))

    return document_to_string(html).replace("&amp;", "&")

