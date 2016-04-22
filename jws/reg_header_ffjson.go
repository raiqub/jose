// DO NOT EDIT!
// Code generated by ffjson <https://github.com/pquerna/ffjson>
// source: reg_header.go
// DO NOT EDIT!

package jws

import (
	"bytes"
	"fmt"
	fflib "github.com/pquerna/ffjson/fflib/v1"
)

func (mj *RegisteredHeader) MarshalJSON() ([]byte, error) {
	var buf fflib.Buffer
	if mj == nil {
		buf.WriteString("null")
		return buf.Bytes(), nil
	}
	err := mj.MarshalJSONBuf(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (mj *RegisteredHeader) MarshalJSONBuf(buf fflib.EncodingBuffer) error {
	if mj == nil {
		buf.WriteString("null")
		return nil
	}
	var err error
	var obj []byte
	_ = obj
	_ = err
	buf.WriteString(`{ `)
	if len(mj.ID) != 0 {
		buf.WriteString(`"kid":`)
		fflib.WriteJsonString(buf, string(mj.ID))
		buf.WriteByte(',')
	}
	if len(mj.Type) != 0 {
		buf.WriteString(`"typ":`)
		fflib.WriteJsonString(buf, string(mj.Type))
		buf.WriteByte(',')
	}
	if len(mj.ContentType) != 0 {
		buf.WriteString(`"cty":`)
		fflib.WriteJsonString(buf, string(mj.ContentType))
		buf.WriteByte(',')
	}
	buf.WriteString(`"alg":`)
	fflib.WriteJsonString(buf, string(mj.Algorithm))
	buf.WriteByte(',')
	if len(mj.JWKSetURL) != 0 {
		buf.WriteString(`"jku":`)
		fflib.WriteJsonString(buf, string(mj.JWKSetURL))
		buf.WriteByte(',')
	}
	if len(mj.JWK) != 0 {
		buf.WriteString(`"jwk":`)
		fflib.WriteJsonString(buf, string(mj.JWK))
		buf.WriteByte(',')
	}
	if len(mj.X509URL) != 0 {
		buf.WriteString(`"x5u":`)
		fflib.WriteJsonString(buf, string(mj.X509URL))
		buf.WriteByte(',')
	}
	if len(mj.X509Chain) != 0 {
		buf.WriteString(`"x5c":`)
		fflib.WriteJsonString(buf, string(mj.X509Chain))
		buf.WriteByte(',')
	}
	if len(mj.X509SHA1) != 0 {
		buf.WriteString(`"x5t":`)
		fflib.WriteJsonString(buf, string(mj.X509SHA1))
		buf.WriteByte(',')
	}
	if len(mj.X509SHA256) != 0 {
		buf.WriteString(`"x5t#S256":`)
		fflib.WriteJsonString(buf, string(mj.X509SHA256))
		buf.WriteByte(',')
	}
	if len(mj.Critical) != 0 {
		buf.WriteString(`"crit":`)
		if mj.Critical != nil {
			buf.WriteString(`[`)
			for i, v := range mj.Critical {
				if i != 0 {
					buf.WriteString(`,`)
				}
				fflib.WriteJsonString(buf, string(v))
			}
			buf.WriteString(`]`)
		} else {
			buf.WriteString(`null`)
		}
		buf.WriteByte(',')
	}
	buf.Rewind(1)
	buf.WriteByte('}')
	return nil
}

const (
	ffj_t_RegisteredHeaderbase = iota
	ffj_t_RegisteredHeaderno_such_key

	ffj_t_RegisteredHeader_ID

	ffj_t_RegisteredHeader_Type

	ffj_t_RegisteredHeader_ContentType

	ffj_t_RegisteredHeader_Algorithm

	ffj_t_RegisteredHeader_JWKSetURL

	ffj_t_RegisteredHeader_JWK

	ffj_t_RegisteredHeader_X509URL

	ffj_t_RegisteredHeader_X509Chain

	ffj_t_RegisteredHeader_X509SHA1

	ffj_t_RegisteredHeader_X509SHA256

	ffj_t_RegisteredHeader_Critical
)

var ffj_key_RegisteredHeader_ID = []byte("kid")

var ffj_key_RegisteredHeader_Type = []byte("typ")

var ffj_key_RegisteredHeader_ContentType = []byte("cty")

var ffj_key_RegisteredHeader_Algorithm = []byte("alg")

var ffj_key_RegisteredHeader_JWKSetURL = []byte("jku")

var ffj_key_RegisteredHeader_JWK = []byte("jwk")

var ffj_key_RegisteredHeader_X509URL = []byte("x5u")

var ffj_key_RegisteredHeader_X509Chain = []byte("x5c")

var ffj_key_RegisteredHeader_X509SHA1 = []byte("x5t")

var ffj_key_RegisteredHeader_X509SHA256 = []byte("x5t#S256")

var ffj_key_RegisteredHeader_Critical = []byte("crit")

func (uj *RegisteredHeader) UnmarshalJSON(input []byte) error {
	fs := fflib.NewFFLexer(input)
	return uj.UnmarshalJSONFFLexer(fs, fflib.FFParse_map_start)
}

func (uj *RegisteredHeader) UnmarshalJSONFFLexer(fs *fflib.FFLexer, state fflib.FFParseState) error {
	var err error = nil
	currentKey := ffj_t_RegisteredHeaderbase
	_ = currentKey
	tok := fflib.FFTok_init
	wantedTok := fflib.FFTok_init

mainparse:
	for {
		tok = fs.Scan()
		//	println(fmt.Sprintf("debug: tok: %v  state: %v", tok, state))
		if tok == fflib.FFTok_error {
			goto tokerror
		}

		switch state {

		case fflib.FFParse_map_start:
			if tok != fflib.FFTok_left_bracket {
				wantedTok = fflib.FFTok_left_bracket
				goto wrongtokenerror
			}
			state = fflib.FFParse_want_key
			continue

		case fflib.FFParse_after_value:
			if tok == fflib.FFTok_comma {
				state = fflib.FFParse_want_key
			} else if tok == fflib.FFTok_right_bracket {
				goto done
			} else {
				wantedTok = fflib.FFTok_comma
				goto wrongtokenerror
			}

		case fflib.FFParse_want_key:
			// json {} ended. goto exit. woo.
			if tok == fflib.FFTok_right_bracket {
				goto done
			}
			if tok != fflib.FFTok_string {
				wantedTok = fflib.FFTok_string
				goto wrongtokenerror
			}

			kn := fs.Output.Bytes()
			if len(kn) <= 0 {
				// "" case. hrm.
				currentKey = ffj_t_RegisteredHeaderno_such_key
				state = fflib.FFParse_want_colon
				goto mainparse
			} else {
				switch kn[0] {

				case 'a':

					if bytes.Equal(ffj_key_RegisteredHeader_Algorithm, kn) {
						currentKey = ffj_t_RegisteredHeader_Algorithm
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				case 'c':

					if bytes.Equal(ffj_key_RegisteredHeader_ContentType, kn) {
						currentKey = ffj_t_RegisteredHeader_ContentType
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_RegisteredHeader_Critical, kn) {
						currentKey = ffj_t_RegisteredHeader_Critical
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				case 'j':

					if bytes.Equal(ffj_key_RegisteredHeader_JWKSetURL, kn) {
						currentKey = ffj_t_RegisteredHeader_JWKSetURL
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_RegisteredHeader_JWK, kn) {
						currentKey = ffj_t_RegisteredHeader_JWK
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				case 'k':

					if bytes.Equal(ffj_key_RegisteredHeader_ID, kn) {
						currentKey = ffj_t_RegisteredHeader_ID
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				case 't':

					if bytes.Equal(ffj_key_RegisteredHeader_Type, kn) {
						currentKey = ffj_t_RegisteredHeader_Type
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				case 'x':

					if bytes.Equal(ffj_key_RegisteredHeader_X509URL, kn) {
						currentKey = ffj_t_RegisteredHeader_X509URL
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_RegisteredHeader_X509Chain, kn) {
						currentKey = ffj_t_RegisteredHeader_X509Chain
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_RegisteredHeader_X509SHA1, kn) {
						currentKey = ffj_t_RegisteredHeader_X509SHA1
						state = fflib.FFParse_want_colon
						goto mainparse

					} else if bytes.Equal(ffj_key_RegisteredHeader_X509SHA256, kn) {
						currentKey = ffj_t_RegisteredHeader_X509SHA256
						state = fflib.FFParse_want_colon
						goto mainparse
					}

				}

				if fflib.SimpleLetterEqualFold(ffj_key_RegisteredHeader_Critical, kn) {
					currentKey = ffj_t_RegisteredHeader_Critical
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_RegisteredHeader_X509SHA256, kn) {
					currentKey = ffj_t_RegisteredHeader_X509SHA256
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.AsciiEqualFold(ffj_key_RegisteredHeader_X509SHA1, kn) {
					currentKey = ffj_t_RegisteredHeader_X509SHA1
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.AsciiEqualFold(ffj_key_RegisteredHeader_X509Chain, kn) {
					currentKey = ffj_t_RegisteredHeader_X509Chain
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.AsciiEqualFold(ffj_key_RegisteredHeader_X509URL, kn) {
					currentKey = ffj_t_RegisteredHeader_X509URL
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_RegisteredHeader_JWK, kn) {
					currentKey = ffj_t_RegisteredHeader_JWK
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_RegisteredHeader_JWKSetURL, kn) {
					currentKey = ffj_t_RegisteredHeader_JWKSetURL
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.SimpleLetterEqualFold(ffj_key_RegisteredHeader_Algorithm, kn) {
					currentKey = ffj_t_RegisteredHeader_Algorithm
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.SimpleLetterEqualFold(ffj_key_RegisteredHeader_ContentType, kn) {
					currentKey = ffj_t_RegisteredHeader_ContentType
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.SimpleLetterEqualFold(ffj_key_RegisteredHeader_Type, kn) {
					currentKey = ffj_t_RegisteredHeader_Type
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				if fflib.EqualFoldRight(ffj_key_RegisteredHeader_ID, kn) {
					currentKey = ffj_t_RegisteredHeader_ID
					state = fflib.FFParse_want_colon
					goto mainparse
				}

				currentKey = ffj_t_RegisteredHeaderno_such_key
				state = fflib.FFParse_want_colon
				goto mainparse
			}

		case fflib.FFParse_want_colon:
			if tok != fflib.FFTok_colon {
				wantedTok = fflib.FFTok_colon
				goto wrongtokenerror
			}
			state = fflib.FFParse_want_value
			continue
		case fflib.FFParse_want_value:

			if tok == fflib.FFTok_left_brace || tok == fflib.FFTok_left_bracket || tok == fflib.FFTok_integer || tok == fflib.FFTok_double || tok == fflib.FFTok_string || tok == fflib.FFTok_bool || tok == fflib.FFTok_null {
				switch currentKey {

				case ffj_t_RegisteredHeader_ID:
					goto handle_ID

				case ffj_t_RegisteredHeader_Type:
					goto handle_Type

				case ffj_t_RegisteredHeader_ContentType:
					goto handle_ContentType

				case ffj_t_RegisteredHeader_Algorithm:
					goto handle_Algorithm

				case ffj_t_RegisteredHeader_JWKSetURL:
					goto handle_JWKSetURL

				case ffj_t_RegisteredHeader_JWK:
					goto handle_JWK

				case ffj_t_RegisteredHeader_X509URL:
					goto handle_X509URL

				case ffj_t_RegisteredHeader_X509Chain:
					goto handle_X509Chain

				case ffj_t_RegisteredHeader_X509SHA1:
					goto handle_X509SHA1

				case ffj_t_RegisteredHeader_X509SHA256:
					goto handle_X509SHA256

				case ffj_t_RegisteredHeader_Critical:
					goto handle_Critical

				case ffj_t_RegisteredHeaderno_such_key:
					err = fs.SkipField(tok)
					if err != nil {
						return fs.WrapErr(err)
					}
					state = fflib.FFParse_after_value
					goto mainparse
				}
			} else {
				goto wantedvalue
			}
		}
	}

handle_ID:

	/* handler: uj.ID type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.ID = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_Type:

	/* handler: uj.Type type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.Type = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_ContentType:

	/* handler: uj.ContentType type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.ContentType = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_Algorithm:

	/* handler: uj.Algorithm type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.Algorithm = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_JWKSetURL:

	/* handler: uj.JWKSetURL type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.JWKSetURL = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_JWK:

	/* handler: uj.JWK type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.JWK = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_X509URL:

	/* handler: uj.X509URL type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.X509URL = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_X509Chain:

	/* handler: uj.X509Chain type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.X509Chain = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_X509SHA1:

	/* handler: uj.X509SHA1 type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.X509SHA1 = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_X509SHA256:

	/* handler: uj.X509SHA256 type=string kind=string quoted=false*/

	{

		{
			if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
			}
		}

		if tok == fflib.FFTok_null {

		} else {

			outBuf := fs.Output.Bytes()

			uj.X509SHA256 = string(string(outBuf))

		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

handle_Critical:

	/* handler: uj.Critical type=[]string kind=slice quoted=false*/

	{

		{
			if tok != fflib.FFTok_left_brace && tok != fflib.FFTok_null {
				return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for ", tok))
			}
		}

		if tok == fflib.FFTok_null {
			uj.Critical = nil
		} else {

			uj.Critical = make([]string, 0)

			wantVal := true

			for {

				var v string

				tok = fs.Scan()
				if tok == fflib.FFTok_error {
					goto tokerror
				}
				if tok == fflib.FFTok_right_brace {
					break
				}

				if tok == fflib.FFTok_comma {
					if wantVal == true {
						// TODO(pquerna): this isn't an ideal error message, this handles
						// things like [,,,] as an array value.
						return fs.WrapErr(fmt.Errorf("wanted value token, but got token: %v", tok))
					}
					continue
				} else {
					wantVal = true
				}

				/* handler: v type=string kind=string quoted=false*/

				{

					{
						if tok != fflib.FFTok_string && tok != fflib.FFTok_null {
							return fs.WrapErr(fmt.Errorf("cannot unmarshal %s into Go value for string", tok))
						}
					}

					if tok == fflib.FFTok_null {

					} else {

						outBuf := fs.Output.Bytes()

						v = string(string(outBuf))

					}
				}

				uj.Critical = append(uj.Critical, v)
				wantVal = false
			}
		}
	}

	state = fflib.FFParse_after_value
	goto mainparse

wantedvalue:
	return fs.WrapErr(fmt.Errorf("wanted value token, but got token: %v", tok))
wrongtokenerror:
	return fs.WrapErr(fmt.Errorf("ffjson: wanted token: %v, but got token: %v output=%s", wantedTok, tok, fs.Output.String()))
tokerror:
	if fs.BigError != nil {
		return fs.WrapErr(fs.BigError)
	}
	err = fs.Error.ToError()
	if err != nil {
		return fs.WrapErr(err)
	}
	panic("ffjson-generated: unreachable, please report bug.")
done:
	return nil
}
