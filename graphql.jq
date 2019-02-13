# go_name takes a string and converts it to pascal case and replaces some strings
def go_name:
	# Prefix a _ causing the first char to be uppercase
	"_" + . | gsub("[_-]+(?<a>[A-Za-z])"; .a|ascii_upcase) | 
	# These words are abbreviatons, should be in all caps
	# Add your own as you see fit for your use-case
	gsub("(?<a>(Id|Sla|Url|Cve|Otp|Csrf|Totp))(?=[A-Z]|$)"; .a|ascii_upcase);

# go_custom_type handles specific scalars that map to existing go types
def go_custom_type:
	# These are some "known"/common mappings
	# Add your own as you see fit for your use-case
	if . == "String" then
		"string"
	elif . == "ID" then
		"string"
	elif . == "Hash" then
		"string""
	elif . == "Int" then
		"int32"
	elif . == "CountBySeverity" then
		"int32
	elif . == "Float" then
		"float64"
	elif . == "Boolean" then
		"bool"
	else
		null
	end;

# go_type returns a Golang type object for a given "type" field
def go_type:
	# If it's the NON_NULL kind just recurse with the wrapper
	if .kind == "NON_NULL" then
		.ofType | go_type
	elif .kind == "LIST" then
		"[]" + (.ofType | go_type)
	else
		# These are types we can map directly to go types
		# Modify these values as you see fit
		.name | "*" + (go_custom_type // go_name)
	end;

# go_comment returns a comment for a given description and deprecation
def go_comment:
	# Prefix each line of the description with a //
	((.description // "") | split("\n") | map(
		"// " + .
	)) + 
	# This isn't technically in the spec, but it's common
	if .isDeprecated then
		(.deprecationReason // "") | split("\n") | map(
			"// DEPRECATED: " + .
		)
	else [] end;

# go_enum_value generates a const valye
def go_enum_value(enum):
	go_comment + [
		# We want the name in pascal case
		(enum.name | go_name) + (.name | go_name) + " " +
		# It is of the "enum" type
		(enum.name | go_name) + " = " +
		# We use tojson to convert to safe strings
		(.name | tojson)
	];

# go_enum generates a Golang "enum" object
def go_enum:
	. as $obj | 
	go_comment + [
		# TODO: We assume all enums are strings, not necessarily
		"type " + (.name | go_name) + " string",
		"const (",
		(
			.enumValues | map(go_enum_value($obj)) | add
		),
		")"
	];

# go_struct_tag generates a json tag for an object
def go_struct_tag:
	# We use omitempty here to not send blank fields
	"`json:\"" + .name + ",omitempty\"`";

# go_struct_field generates a field in a struct
def go_struct_field:
	go_comment + [
		# Field names should be pascal case
		(.name | go_name) + " " +
		# Let go_type figure out the type
		(.type | go_type) + " " + 
		# Add the json tag
		go_struct_tag
	];

# go_union_field generates the union fields
def go_union_field:
	[
		"__typename string `json:\"__typename,omitempty\"`"
	] + (.possibleTypes | map(
		(.name | go_name) as $name |
		$name + " *" + $name + " `json:\"-\"`"
	));

# go_union_func generates the union unmarshal functions
def go_union_func($name):
	[
		"",
		"func (u *" + $name + ") UnmarshalJSON(data []byte) (err error) {",
		[
			"type tmpType " + $name,
			"err = json.Unmarshal(data, (*tmpType)(u))",
			"if err != nil {",
				["return err"],
			"}",
			"var payload interface{}",
			"switch tmp.__typename {",
			(.possibleTypes[] | (
				(.name | go_name) as $tName |
				"case \"" + $tName + "\":",
				[
					"u." + $tName + " = &" + $tName + "{}",
					"payload = u." + $tName
				]
			)),
			"}",
			"err = json.Unmarshal(data, payload)",
			"if err != nil {",
				["return err"],
			"}",
			"return nil"
		],
		"}"
	];

# go_struct generates a Golang "struct" object
def go_struct:
	((.fields // []) + (.inputFields // [])) as $fields | 
	(.name | go_name) as $name |
	go_comment + [
		"type " + $name + " struct {",
		(
			($fields | map(go_struct_field) | add) + 
			# Some structs (union/interfaces) have types
			if .possibleTypes then go_union_field else [] end
		), 
		"}"
	] + if .possibleTypes then 
		go_union_func($name) 
	else 
		[] 
	end;

# go_schema iterates over a introspection "schema" object
def go_schema:
	[
		"package h1",
		"",
		"import (",
		["\"encoding/json\""],
		")"
	] +
	(.types | map(["", ""] +
		if 
		 .kind == "OBJECT" or 
		 .kind == "INPUT_OBJECT" or
		 .kind == "UNION" 
		then
			go_struct
		elif 
		 .kind == "ENUM" 
		then
			go_enum
		else
			[]
		end
	) | add);

# print(prefix) takes a nested array of arrays as a single string with newlines and indentation for the relevant level
def print(prefix):
	# Use reduce to append everything into a single string
	reduce .[] as $item (
		# Starting with a empty string
		"";
		# Append either the string or recurse
		. + ($item | if type == "array" then
			# Add another level of indent on the recursion
			print("\t" + prefix)
		else
			# Add the string along with the prefix and a newline
			prefix + . + "\n"
		end)
	);

# print calls print with a blank prefix removing the trailing newline
def print: print("") | rtrimstr("\n");

# Take the input, pass to go_schema and print the results
.__schema | go_schema | print