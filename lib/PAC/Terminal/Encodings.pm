package PAC::Terminal::Encodings;

###############################################################################
# PAC::Terminal::Encodings — registry of all supported terminal character
# encodings (~250 entries).
#
# Pure data, no Gtk / no asbru state. Mechanical extraction from
# PACUtils::_getEncodings; PACUtils retains a 1-line proxy for the 2
# callsites in PACConfig (preferences UI).
###############################################################################

use strict;
use warnings;
use utf8;

our $VERSION = '0.1.0';

# all() — returns a hashref of { encoding-name => human-readable-source }.
sub all {
    return {
        "Adobe-Standard-Encoding" => "PostScript Language Reference Manual",
        "Adobe-Symbol-Encoding" => "PostScript Language Reference Manual",
        "Amiga-1251" => "See (http://www.amiga.ultranet.ru/Amiga-1251.html)",
        "ANSI_X3.110-1983" => "ECMA registry",
        "ANSI_X3.4-1968" => "ECMA registry",
        "ASMO_449" => "ECMA registry",
        "Big5" => "Chinese for Taiwan Multi-byte set.",
        "Big5-HKSCS" => "See (http://www.iana.org/assignments/charset-reg/Big5-HKSCS)",
        "BOCU-1" => "http://www.unicode.org/notes/tn6/",
        "BRF" => "See <http://www.iana.org/assignments/charset-reg/BRF>",
        "BS_4730" => "ECMA registry",
        "BS_viewdata" => "ECMA registry",
        "CESU-8" => "<http://www.unicode.org/unicode/reports/tr26>",
        "CP51932" => "See <http://www.iana.org/assignments/charset-reg/CP51932>",
        "CSA_Z243.4-1985-1" => "ECMA registry",
        "CSA_Z243.4-1985-2" => "ECMA registry",
        "CSA_Z243.4-1985-gr" => "ECMA registry",
        "CSN_369103" => "ECMA registry",
        "DEC-MCS" => "VAX/VMS User's Manual,",
        "DIN_66003" => "ECMA registry",
        "dk-us" => "",
        "DS_2089" => "Danish Standard, DS 2089, February 1974",
        "EBCDIC-AT-DE-A" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-AT-DE" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-CA-FR" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-DK-NO-A" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-DK-NO" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-ES-A" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-ES" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-ES-S" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-FI-SE-A" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-FI-SE" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-FR" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-IT" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-PT" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-UK" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "EBCDIC-US" => "IBM 3270 Char Set Ref Ch 10, GA27-2837-9, April 1987",
        "ECMA-cyrillic" => "ISO registry (formerly ECMA registry)",
        "ES2" => "ECMA registry",
        "ES" => "ECMA registry",
        "EUC-KR" => "RFC-1557 (see also KS_C_5861-1992)",
        "Extended_UNIX_Code_Fixed_Width_for_Japanese" => "Used in Japan.  Each character is 2 octets.",
        "Extended_UNIX_Code_Packed_Format_for_Japanese" => "Standardized by OSF, UNIX International, and UNIX Systems",
        "GB18030" => "Chinese IT Standardization Technical Committee",
        "GB_1988-80" => "ECMA registry",
        "GB_2312-80" => "ECMA registry",
        "GB2312" => "Chinese for People's Republic of China (PRC) mixed one byte,",
        "GBK" => "Chinese IT Standardization Technical Committee",
        "GOST_19768-74" => "ECMA registry",
        "greek7" => "ECMA registry",
        "greek7-old" => "ECMA registry",
        "greek-ccitt" => "ECMA registry",
        "HP-DeskTop" => "PCL 5 Comparison Guide, Hewlett-Packard,",
        "HP-Legal" => "PCL 5 Comparison Guide, Hewlett-Packard,",
        "HP-Math8" => "PCL 5 Comparison Guide, Hewlett-Packard,",
        "HP-Pi-font" => "PCL 5 Comparison Guide, Hewlett-Packard,",
        "hp-roman8" => "LaserJet IIP Printer User's Manual,",
        "HZ-GB-2312" => "RFC 1842, RFC 1843",
        "IBM00858" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM00858)",
        "IBM00924" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM00924)",
        "IBM01140" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01140)",
        "IBM01141" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01141)",
        "IBM01142" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01142)",
        "IBM01143" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01143)",
        "IBM01144" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01144)",
        "IBM01145" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01145)",
        "IBM01146" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01146)",
        "IBM01147" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01147)",
        "IBM01148" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01148)",
        "IBM01149" => "IBM See (http://www.iana.org/assignments/charset-reg/IBM01149)",
        "IBM037" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM038" => "IBM 3174 Character Set Ref, GA27-3831-02, March 1990",
        "IBM1026" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM1047" => "IBM1047 (EBCDIC Latin 1/Open Systems)",
        "IBM273" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM274" => "IBM 3174 Character Set Ref, GA27-3831-02, March 1990",
        "IBM275" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM277" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM278" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM280" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM281" => "IBM 3174 Character Set Ref, GA27-3831-02, March 1990",
        "IBM284" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM285" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM290" => "IBM 3174 Character Set Ref, GA27-3831-02, March 1990",
        "IBM297" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM420" => "IBM NLS RM Vol2 SE09-8002-01, March 1990,",
        "IBM423" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM424" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM437" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM500" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM775" => "HP PCL 5 Comparison Guide (P/N 5021-0329) pp B-13, 1996",
        "IBM850" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM851" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM852" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM855" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM857" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM860" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM861" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM862" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM863" => "IBM Keyboard layouts and code pages, PN 07G4586 June 1991",
        "IBM864" => "IBM Keyboard layouts and code pages, PN 07G4586 June 1991",
        "IBM865" => "IBM DOS 3.3 Ref (Abridged), 94X9575 (Feb 1987)",
        "IBM866" => "IBM NLDG Volume 2 (SE09-8002-03) August 1994",
        "IBM868" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM869" => "IBM Keyboard layouts and code pages, PN 07G4586 June 1991",
        "IBM870" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM871" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM880" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM891" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM903" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM904" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM905" => "IBM 3174 Character Set Ref, GA27-3831-02, March 1990",
        "IBM918" => "IBM NLS RM Vol2 SE09-8002-01, March 1990",
        "IBM-Symbols" => "Presentation Set, CPGID: 259",
        "IBM-Thai" => "Presentation Set, CPGID: 838",
        "IEC_P27-1" => "ECMA registry",
        "INIS-8" => "ECMA registry",
        "INIS-cyrillic" => "ECMA registry",
        "INIS" => "ECMA registry",
        "INVARIANT" => "",
        "ISO_10367-box" => "ECMA registry",
        "ISO-10646-J-1" => "ISO 10646 Japanese, see RFC 1815.",
        "ISO-10646-UCS-2" => "the 2-octet Basic Multilingual Plane, aka Unicode",
        "ISO-10646-UCS-4" => "the full code space. (same comment about byte order,",
        "ISO-10646-UCS-Basic" => "ASCII subset of Unicode.  Basic Latin = collection 1",
        "ISO-10646-Unicode-Latin1" => "ISO Latin-1 subset of Unicode. Basic Latin and Latin-1",
        "ISO-10646-UTF-1" => "Universal Transfer Format (1), this is the multibyte",
        "ISO-11548-1" => "See <http://www.iana.org/assignments/charset-reg/ISO-11548-1>",
        "ISO-2022-CN-EXT" => "RFC-1922",
        "ISO-2022-CN" => "RFC-1922",
        "ISO-2022-JP-2" => "RFC-1554",
        "ISO-2022-JP" => "RFC-1468 (see also RFC-2237)",
        "ISO-2022-KR" => "RFC-1557 (see also KS_C_5601-1987)",
        "ISO_2033-1983" => "ECMA registry",
        "ISO_5427:1981" => "ECMA registry",
        "ISO_5427" => "ECMA registry",
        "ISO_5428:1980" => "ECMA registry",
        "ISO_646.basic:1983" => "ECMA registry",
        "ISO_646.irv:1983" => "ECMA registry",
        "ISO_6937-2-25" => "ECMA registry",
        "ISO_6937-2-add" => "ECMA registry and ISO 6937-2:1983",
        "ISO-8859-10" => "ECMA registry",
        "ISO_8859-1:1987" => "ECMA registry",
        "ISO-8859-13" => "ISO See (http://www.iana.org/assignments/charset-reg/ISO-8859-13)",
        "ISO-8859-14" => "ISO See (http://www.iana.org/assignments/charset-reg/ISO-8859-14)",
        "ISO-8859-15" => "ISO",
        "ISO-8859-16" => "ISO",
        "ISO-8859-1-Windows-3.0-Latin-1" => "Extended ISO 8859-1 Latin-1 for Windows 3.0.",
        "ISO-8859-1-Windows-3.1-Latin-1" => "Extended ISO 8859-1 Latin-1 for Windows 3.1.",
        "ISO_8859-2:1987" => "ECMA registry",
        "ISO-8859-2-Windows-Latin-2" => "Extended ISO 8859-2.  Latin-2 for Windows 3.1.",
        "ISO_8859-3:1988" => "ECMA registry",
        "ISO_8859-4:1988" => "ECMA registry",
        "ISO_8859-5:1988" => "ECMA registry",
        "ISO_8859-6:1987" => "ECMA registry",
        "ISO_8859-6-E" => "RFC1556",
        "ISO_8859-6-I" => "RFC1556",
        "ISO_8859-7:1987" => "ECMA registry",
        "ISO_8859-8:1988" => "ECMA registry",
        "ISO_8859-8-E" => "RFC1556",
        "ISO_8859-8-I" => "RFC1556",
        "ISO_8859-9:1989" => "ECMA registry",
        "ISO-8859-9-Windows-Latin-5" => "Extended ISO 8859-9.  Latin-5 for Windows 3.1",
        "ISO_8859-supp" => "ECMA registry",
        "iso-ir-90" => "ECMA registry",
        "ISO-Unicode-IBM-1261" => "IBM Latin-2, -3, -5, Extended Presentation Set, GCSGID: 1261",
        "ISO-Unicode-IBM-1264" => "IBM Arabic Presentation Set, GCSGID: 1264",
        "ISO-Unicode-IBM-1265" => "IBM Hebrew Presentation Set, GCSGID: 1265",
        "ISO-Unicode-IBM-1268" => "IBM Latin-4 Extended Presentation Set, GCSGID: 1268",
        "ISO-Unicode-IBM-1276" => "IBM Cyrillic Greek Extended Presentation Set, GCSGID: 1276",
        "IT" => "ECMA registry",
        "JIS_C6220-1969-jp" => "ECMA registry",
        "JIS_C6220-1969-ro" => "ECMA registry",
        "JIS_C6226-1978" => "ECMA registry",
        "JIS_C6226-1983" => "ECMA registry",
        "JIS_C6229-1984-a" => "ECMA registry",
        "JIS_C6229-1984-b-add" => "ECMA registry",
        "JIS_C6229-1984-b" => "ECMA registry",
        "JIS_C6229-1984-hand-add" => "ECMA registry",
        "JIS_C6229-1984-hand" => "ECMA registry",
        "JIS_C6229-1984-kana" => "ECMA registry",
        "JIS_Encoding" => "JIS X 0202-1991",
        "JIS_X0201" => "JIS X 0201-1976. One byte only",
        "JIS_X0212-1990" => "ECMA registry",
        "JUS_I.B1.002" => "ECMA registry",
        "JUS_I.B1.003-mac" => "ECMA registry",
        "JUS_I.B1.003-serb" => "ECMA registry",
        "KOI7-switched" => "See <http://www.iana.org/assignments/charset-reg/KOI7-switched>",
        "KOI8-R" => "RFC 1489, based on GOST-19768-74, ISO-6937/8,",
        "KOI8-U" => "RFC 2319",
        "KS_C_5601-1987" => "ECMA registry",
        "KSC5636" => "",
        "KZ-1048" => "See <http://www.iana.org/assignments/charset-reg/KZ-1048>",
        "Latin-greek-1" => "ECMA registry",
        "latin-greek" => "ECMA registry",
        "latin-lap" => "ECMA registry",
        "macintosh" => "The Unicode Standard ver1.0, ISBN 0-201-56788-1, Oct 1991",
        "Microsoft-Publishing" => "PCL 5 Comparison Guide, Hewlett-Packard,",
        "MNEMONIC" => "RFC 1345, also known as 'mnemonic+ascii+38'",
        "MNEM" => "RFC 1345, also known as 'mnemonic+ascii+8200'",
        "MSZ_7795.3" => "ECMA registry",
        "NATS-DANO-ADD" => "ECMA registry",
        "NATS-DANO" => "ECMA registry",
        "NATS-SEFI-ADD" => "ECMA registry",
        "NATS-SEFI" => "ECMA registry",
        "NC_NC00-10:81" => "ECMA registry",
        "NF_Z_62-010_(1973)" => "ECMA registry",
        "NF_Z_62-010" => "ECMA registry",
        "NS_4551-1" => "ECMA registry",
        "NS_4551-2" => "ECMA registry",
        "OSD_EBCDIC_DF03_IRV" => "Fujitsu-Siemens standard mainframe EBCDIC encoding",
        "OSD_EBCDIC_DF04_15" => "Fujitsu-Siemens standard mainframe EBCDIC encoding",
        "OSD_EBCDIC_DF04_1" => "Fujitsu-Siemens standard mainframe EBCDIC encoding",
        "PC8-Danish-Norwegian" => "PC Danish Norwegian",
        "PC8-Turkish" => "PC Latin Turkish.  PCL Symbol Set id: 9T",
        "PT2" => "ECMA registry",
        "PTCP154" => "See (http://www.iana.org/assignments/charset-reg/PTCP154)",
        "PT" => "ECMA registry",
        "SCSU" => "SCSU See (http://www.iana.org/assignments/charset-reg/SCSU)",
        "SEN_850200_B" => "ECMA registry",
        "SEN_850200_C" => "ECMA registry",
        "Shift_JIS" => "This charset is an extension of csHalfWidthKatakana",
        "T.101-G2" => "ECMA registry",
        "T.61-7bit" => "ECMA registry",
        "T.61-8bit" => "ECMA registry",
        "TIS-620" => "Thai Industrial Standards Institute (TISI)",
        "TSCII" => "See <http://www.iana.org/assignments/charset-reg/TSCII>",
        "UNICODE-1-1" => "RFC 1641",
        "UNICODE-1-1-UTF-7" => "RFC 1642",
        "UNKNOWN-8BIT" => "",
        "us-dk" => "",
        "UTF-16BE" => "RFC 2781",
        "UTF-16LE" => "RFC 2781",
        "UTF-16" => "RFC 2781",
        "UTF-32BE" => "<http://www.unicode.org/unicode/reports/tr19/>",
        "UTF-32" => "<http://www.unicode.org/unicode/reports/tr19/>",
        "UTF-32LE" => "<http://www.unicode.org/unicode/reports/tr19/>",
        "UTF-7" => "RFC 2152",
        "UTF-8" => "RFC 3629",
        "Ventura-International" => "Ventura International.  ASCII plus coded characters similar",
        "Ventura-Math" => "PCL 5 Comparison Guide, Hewlett-Packard,",
        "Ventura-US" => "Ventura US.  ASCII plus characters typically used in",
        "videotex-suppl" => "ECMA registry",
        "VIQR" => "RFC 1456",
        "VISCII" => "RFC 1456",
        "windows-1250" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1250)",
        "windows-1251" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1251)",
        "windows-1252" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1252)",
        "windows-1253" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1253)",
        "windows-1254" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1254)",
        "windows-1255" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1255)",
        "windows-1256" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1256)",
        "windows-1257" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1257)",
        "windows-1258" => "Microsoft  (http://www.iana.org/assignments/charset-reg/windows-1258)",
        "Windows-31J" => "Windows Japanese.  A further extension of Shift_JIS",
        "windows-874" => "See <http://www.iana.org/assignments/charset-reg/windows-874>",
    };
}

1;

__END__

=encoding utf8

=head1 NAME

PAC::Terminal::Encodings — registry of supported terminal character encodings

=head1 SYNOPSIS

    use PAC::Terminal::Encodings;

    my $encodings = PAC::Terminal::Encodings::all();
    say "$_: $encodings->{$_}" for sort keys %$encodings;

=head1 DESCRIPTION

Static registry of ~250 character-encoding names (UTF-8, ISO-8859-*,
Big5, EUC-JP, KOI8-R, …) with their authoritative source (IANA, ECMA,
RFC, …). Used by C<PACConfig> to populate the per-terminal "encoding"
combo box.

Pure data. No side effects, no asbru-internal dependencies.

=head1 PUBLIC API

=over

=item all

Returns a hashref of C<{ encoding-name =E<gt> source-text }>. The
keys are valid VTE encoding identifiers; the values are documentation
strings shown in the UI tooltip.

=back

=head1 SEE ALSO

L<https://www.iana.org/assignments/character-sets>.

=cut
