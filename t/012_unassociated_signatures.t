# -*- perl -*-

use Test::Lib;
use Test::XML::Sig;


my $xml = slurp_file('t/signed/unassociated-signature-issue.xml');

my $sig = XML::Sig->new({ x509 => 1 });
ok(!$sig->verify($xml), "Single Unassociated Signature Fails");
ok(!$sig->signer_cert, "No Signing Certificate Found");

open my $file2, 't/signed/one-of-three-sigs-unassocated.xml' or die "Cannot open XML file";
my $xml2;
{
    local undef $/;
    $xml2 = <$file2>;
}
my $sig2 = XML::Sig->new({ x509 => 1 });
my $ret2 = $sig2->verify($xml2);
ok($ret2 , "One of three Unassociated Signatures Passes");
ok($sig2->signer_cert, "No Signing Certificate Found");

done_testing;
