use Test::Lib;
use Test::XML::Sig;
use utf8;  # so literal Unicode characters in this source file are decoded
use Encode qw(encode_utf8);

my $sig = XML::Sig->new(
    { x509 => 1, key => 't/ecdsa.private.pem', cert => 't/ecdsa.public.pem' });
isa_ok( $sig, 'XML::Sig' );

eval {
    $sig->sign('<foo ID="123"></foo>');
};
like ($@, qr/XML ID format is invalid/, 'ID cannot begin with a number');

eval {
    $sig->sign('<foo ID="123_foo"></foo>');
};
like ($@, qr/XML ID format is invalid/, 'ID cannot begin with a number');

eval {
    $sig->sign('<foo ID="_123"></foo>');
};
unlike ($@, qr/XML ID format is invalid/, 'ID can begin with an underscore');

eval {
    $sig->sign('<foo ID="a_123"></foo>');
};
unlike ($@, qr/XML ID format is invalid/, 'ID can begin with a lowercase letter');

eval {
    $sig->sign('<foo ID="Z_123"></foo>');
};
unlike ($@, qr/XML ID format is invalid/, 'ID can begin with a uppercase letter');

eval {
    $sig->sign('<foo ID="Z_123.abYZ-xor"></foo>');
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain "-" and "." characters');

eval {
    $sig->sign('<foo ID="Z_123~abYZ-xor"></foo>');
};
like ($@, qr/XML ID format is invalid/, 'ID cannot contain "~" characters');

eval {
    $sig->sign('<foo ID="Z_123$-bYZ-xor"></foo>');
};
like ($@, qr/XML ID format is invalid/, 'ID cannot contain "$" characters');

use utf8;
use Encode qw(encode_utf8);

# --- Unicode that should be accepted ---

eval {
    $sig->sign(encode_utf8('<foo ID="café_id"></foo>'));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain accented Latin (Latin-1 supplement)');

eval {
    $sig->sign(encode_utf8('<foo ID="ñoño"></foo>'));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can begin with an accented Latin character');

eval {
    $sig->sign(encode_utf8('<foo ID="Москва_42"></foo>'));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain Cyrillic characters');

eval {
    $sig->sign(encode_utf8('<foo ID="α_β_γ"></foo>'));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain Greek characters');

eval {
    $sig->sign(encode_utf8('<foo ID="日本語_id"></foo>'));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain CJK characters');

# Combining diacritic (NameChar but NOT NameStartChar) used in middle position
eval {
    $sig->sign(encode_utf8("<foo ID=\"a\x{0301}foo\"></foo>"));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain a combining diacritic after a start char');

# Middle dot (\xB7) is NameChar only
eval {
    $sig->sign(encode_utf8("<foo ID=\"l\x{B7}l\"></foo>"));
};
unlike ($@, qr/XML ID format is invalid/, 'ID can contain middle dot in non-start position');

# --- Unicode that should be rejected ---

# Combining diacritic at the start is NameChar but not NameStartChar
eval {
    $sig->sign(encode_utf8("<foo ID=\"\x{0301}foo\"></foo>"));
};
like ($@, qr/XML ID format is invalid/, 'ID cannot begin with a combining diacritic');

# Middle dot at the start is NameChar but not NameStartChar
eval {
    $sig->sign(encode_utf8("<foo ID=\"\x{B7}foo\"></foo>"));
};
like ($@, qr/XML ID format is invalid/, 'ID cannot begin with middle dot');

# Colon is excluded from NCName entirely
eval {
    $sig->sign(encode_utf8('<foo ID="foo:bar"></foo>'));
};
like ($@, qr/XML ID format is invalid/, 'ID cannot contain colon (excluded from NCName)');

# A character that's in no NCName production at all (em dash)
eval {
    $sig->sign(encode_utf8("<foo ID=\"foo\x{2014}bar\"></foo>"));
};
like ($@, qr/XML ID format is invalid/, 'ID cannot contain em dash');

done_testing();

