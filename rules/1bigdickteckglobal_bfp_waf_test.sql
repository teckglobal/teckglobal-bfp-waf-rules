-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: 10.0.206.20:4606
-- Generation Time: Jun 14, 2025 at 09:15 AM
-- Server version: 11.8.2-MariaDB-ubu2404
-- PHP Version: 8.3.19

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `teckglobalDB`
--

-- --------------------------------------------------------

--
-- Table structure for table `1bigdickteckglobal_bfp_waf_test`
--

CREATE TABLE `1bigdickteckglobal_bfp_waf_test` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `rule_id` varchar(50) NOT NULL,
  `rule_pattern` text DEFAULT NULL,
  `action` varchar(20) NOT NULL,
  `capture` tinyint(1) DEFAULT 0,
  `transformations` text DEFAULT NULL,
  `score` int(11) NOT NULL DEFAULT 5,
  `paranoia_level` tinyint(4) NOT NULL DEFAULT 1,
  `severity` varchar(20) DEFAULT 'NOTICE',
  `category` varchar(255) DEFAULT NULL,
  `phase` tinyint(4) DEFAULT 1,
  `tags` text DEFAULT NULL,
  `version` varchar(50) DEFAULT NULL,
  `chain_level` tinyint(4) DEFAULT 0,
  `parent_rule_id` varchar(50) DEFAULT NULL,
  `logdata` varchar(255) DEFAULT NULL,
  `msg` varchar(255) DEFAULT '',
  `enabled` tinyint(1) DEFAULT 1,
  `multiMatch` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

--
-- Dumping data for table `1bigdickteckglobal_bfp_waf_test`
--

INSERT INTO `1bigdickteckglobal_bfp_waf_test` (`id`, `rule_id`, `rule_pattern`, `action`, `capture`, `transformations`, `score`, `paranoia_level`, `severity`, `category`, `phase`, `tags`, `version`, `chain_level`, `parent_rule_id`, `logdata`, `msg`, `enabled`, `multiMatch`) VALUES
(261, '905100', 'GET /', 'pass', 0, '', 2, 0, 'NOTICE', 'exception', 2, 'operator:streq', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(262, '905110', '127.0.0.1,::1', 'pass', 0, '', 2, 0, 'NOTICE', 'exception', 2, 'operator:ipMatch', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(263, '941011', '1', 'pass', 0, '', 2, 1, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(264, '941012', '1', 'pass', 0, '', 2, 1, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(265, '941010', '', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, '', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(266, '941100', 'detectXSS', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:detectXSS', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(267, '941110', '(?i)<script[^>]*>[\\s\\S]*?', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(268, '941130', '(?i).(?:\\b(?:(?:x(?:link:href|html|mlns)|data:text/html|formaction)\\b|pattern[\\s\\x0b]*=)|(?:!ENTITY[\\s\\x0b]+(?:%[\\s\\x0b]+)?[^\\s\\x0b]+[\\s\\x0b]+(?:SYSTEM|PUBLIC)|@import|;base64)\\b)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(269, '941140', '(?i)[a-z]+=(?:[^:=]+:.+;)*?[^:=]+:url\\(javascript', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(270, '941180', 'document.cookie document.domain document.querySelector document.body.appendChild document.write .parentnode .innerhtml window.location -moz-binding <!-- <![cdata[', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:pm', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(271, '941190', '(?i:<style.*?>.*?(?:@[i\\x5c]|(?:[:=]|&#x?0*(?:58|3A|61|3D);?).*?(?:[(\\x5c]|&#x?0*(?:40|28|92|5C);?)))', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(272, '941200', '(?i:<.*[:]?vmlframe.*?[\\s/+]*?src[\\s/+]*=)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(273, '941210', '(?i)(?:j|&#(?:0*(?:74|106)|x0*[46]A);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:a|&#(?:0*(?:65|97)|x0*[46]1);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:v|&#(?:0*(?:86|118)|x0*[57]6);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:a|&#(?:0*(?:65|97)|x0*[46]1);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:s|&#(?:0*(?:115|83)|x0*[57]3);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:c|&#(?:x0*[46]3|0*(?:99|67));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:r|&#(?:x0*[57]2|0*(?:114|82));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:i|&#(?:x0*[46]9|0*(?:105|73));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:p|&#(?:x0*[57]0|0*(?:112|80));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:t|&#(?:x0*[57]4|0*(?:116|84));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?::|&(?:#(?:0*58|x0*3A);?|colon;)).', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(274, '941220', '(?i)(?:v|&#(?:0*(?:118|86)|x0*[57]6);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:b|&#(?:0*(?:98|66)|x0*[46]2);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:s|&#(?:0*(?:115|83)|x0*[57]3);)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:c|&#(?:x0*[46]3|0*(?:99|67));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:r|&#(?:x0*[57]2|0*(?:114|82));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:i|&#(?:x0*[46]9|0*(?:105|73));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:p|&#(?:x0*[57]0|0*(?:112|80));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:t|&#(?:x0*[57]4|0*(?:116|84));)(?:[\\t\\n\\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?::|&(?:#(?:0*58|x0*3A);?|colon;)).', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(275, '941230', '(?i)<EMBED[\\s/+].*?(?:src|type).*?=', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(276, '941240', '<[?]?import[\\s/+\\S]*?implementation[\\s/+]*?=', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(277, '941260', '(?i:<META[\\s/+].*?charset[\\s/+]*=)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(278, '941270', '(?i)<LINK[\\s/+].*?href[\\s/+]*=', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(279, '941280', '(?i)<BASE[\\s/+].*?href[\\s/+]*=', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(280, '941290', '(?i)<APPLET[\\s/+>]', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(281, '941300', '(?i)<OBJECT[\\s/+].*?(?:type|codetype|classid|code|data)[\\s/+]*=', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(282, '941310', '\\xbc[^\\xbe>]*[\\xbe>]|<[^\\xbe]*\\xbe', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(283, '941350', '\\+ADw-.*(?:\\+AD4-|>)|<.*\\+AD4-', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(284, '941360', '![!+ ]\\[\\]', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(285, '941370', '(?:self|document|this|top|window)\\s*(?:/\\*|[\\[)]).+?(?:\\]|\\*/)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(286, '941390', '(?i)\\b(?:eval|set(?:timeout|interval)|new[\\s\\x0b]+Function|a(?:lert|tob)|btoa|(?:promp|impor)t|con(?:firm|sole\\.(?:log|dir))|fetch)[\\s\\x0b]*[\\(\\{]', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(287, '941400', '((?:\\[[^\\]]*\\][^.]*\\.)|Reflect[^.]*\\.).*(?:map|sort|apply)[^.]*\\..*call[^`]*`.*`', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(288, '941013', '2', 'pass', 0, '', 2, 2, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(289, '941014', '2', 'pass', 0, '', 2, 2, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(290, '941101', 'detectXSS', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:detectXSS', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(291, '941150', '(?i)\\b(?:s(?:tyle|rc)|href)\\b[\\s\\S]*?=', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(292, '941181', '-->', 'block', 1, 'removeNulls', 5, 2, 'CRITICAL', 'attack-xss', 2, 'application-multi,language-multi,platform-multi,attack-xss,xss-perf-disable,paranoia-level/2,capec/1000/152/242,operator:contains', 'teckglobal_bfp/1.2.0', 0, '0', 'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}', 'Node-Validator Deny List Keywords', 1, 0),
(293, '941320', '<(?:a|abbr|acronym|address|applet|area|audioscope|b|base|basefront|bdo|bgsound|big|blackface|blink|blockquote|body|bq|br|button|caption|center|cite|code|col|colgroup|comment|dd|del|dfn|dir|div|dl|dt|em|embed|fieldset|fn|font|form|frame|frameset|h1|head|hr|html|i|iframe|ilayer|img|input|ins|isindex|kdb|keygen|label|layer|legend|li|limittext|link|listing|map|marquee|menu|meta|multicol|nobr|noembed|noframes|noscript|nosmartquotes|object|ol|optgroup|option|p|param|plaintext|pre|q|rt|ruby|s|samp|script|select|server|shadow|sidebar|small|spacer|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|wbr|xml|xmp)\\W', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(294, '941380', '{{.*?}}', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-xss', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(295, '941015', '3', 'pass', 0, '', 2, 3, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(296, '941016', '3', 'pass', 0, '', 2, 3, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(297, '941017', '4', 'pass', 0, '', 2, 4, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(298, '941018', '4', 'pass', 0, '', 2, 4, 'NOTICE', 'attack-xss', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(299, 'END-REQUEST-941-APPLICATION-ATTACK-XSS', '', 'pass', 0, '', 2, 0, 'NOTICE', 'exception', 2, '', 'teckglobal_bfp/1.2.0', 0, '0', '', 'End of rule set', 1, 0),
(300, '942011', '1', 'pass', 0, '', 2, 1, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(301, '942012', '1', 'pass', 0, '', 2, 1, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(302, '942100', 'detectSQLi', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:detectSQLi', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(303, '942140', '(?i)\\b(?:d(?:atabas|b_nam)e[^0-9A-Z_a-z]*\\(|(?:information_schema|m(?:aster\\.\\.sysdatabases|s(?:db|ys(?:ac(?:cess(?:objects|storage|xml)|es)|modules2?|(?:object|querie|relationship)s))|ysql\\.db)|northwind|pg_(?:catalog|toast)|tempdb)\\b|s(?:chema(?:_name\\b|[^0-9A-Z_a-z]*\\()|(?:qlite_(?:temp_)?master|ys(?:aux|\\.database_name))\\b))', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(304, '942151', '(?i)\\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|iel(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert_tz)?)|t)|r32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|s_(?:de|en)crypt)|ump)|e(?:n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|insert|object(?:_(?:agg|keys))?|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|inser_id)|case|east|i(?:kely|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2))|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:lygon|w)|rocedure_analyse)|qu(?:ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp))|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\\(', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(305, '942160', '(?i:sleep\\(\\s*?\\d*?\\s*?\\)|benchmark\\(.*?\\,.*?\\))', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(306, '942170', '(?i)(?:select|;)[\\s\\x0b]+(?:benchmark|if|sleep)[\\s\\x0b]*?\\([\\s\\x0b]*?\\(?[\\s\\x0b]*?[0-9A-Z_a-z]+', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(307, '942220', '^(?i:-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|2.2250738585072011e-308|1e309)$', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(308, '942230', '(?i)[\\s\\x0b\\(\\)]case[\\s\\x0b]+when.*?then|\\)[\\s\\x0b]*?like[\\s\\x0b]*?\\(|select.*?having[\\s\\x0b]*?[^\\s\\x0b]+[\\s\\x0b]*?[^\\s\\x0b0-9A-Z_a-z]|if[\\s\\x0b]?\\([0-9A-Z_a-z]+[\\s\\x0b]*?[<->~]', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(309, '942270', '(?i)union.*?select.*?from', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(310, '942290', '(?i)\\[?\\$(?:n(?:e|in?|o[rt])|e(?:q|xists|lemMatch)|l(?:te?|ike)|mod|a(?:ll|nd)|(?:s(?:iz|lic)|wher)e|t(?:ype|ext)|x?or|div|between|regex|jsonSchema)\\]?', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(311, '942320', '(?i)create[\\s\\x0b]+(?:function|procedure)[\\s\\x0b]*?[0-9A-Z_a-z]+[\\s\\x0b]*?\\([\\s\\x0b]*?\\)[\\s\\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\\s\\x0b]*?[0-9A-Z_a-z]+|iv[\\s\\x0b]*?\\([\\+\\-]*[\\s\\x0b\\.0-9]+,[\\+\\-]*[\\s\\x0b\\.0-9]+\\))|exec[\\s\\x0b]*?\\([\\s\\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\\s\\x0b]+analyse)[\\s\\x0b]*?\\(|;[\\s\\x0b]*?(?:declare|open)[\\s\\x0b]+[\\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\\s\\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(312, '942350', '(?i)create[\\s\\x0b]+function[\\s\\x0b].+[\\s\\x0b]returns|;[\\s\\x0b]*?(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)\\b[\\s\\x0b]*?[\\(\\[]?[0-9A-Z_a-z]{2,}', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(313, '942500', '(?i)/\\*[\\s\\x0b]*?[!\\+](?:[\\s\\x0b\\(\\)\\-0-9=A-Z_a-z]+)?\\*/', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(314, '942560', '(?i)1\\.e[\\(\\),]', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(315, '942013', '2', 'pass', 0, '', 2, 2, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(316, '942014', '2', 'pass', 0, '', 2, 2, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(317, '942150', '(?i)\\b(?:json(?:_[0-9A-Z_a-z]+)?|a(?:bs|(?:cos|sin)h?|tan[2h]?|vg)|c(?:eil(?:ing)?|h(?:a(?:nges|r(?:set)?)|r)|o(?:alesce|sh?|unt)|ast)|d(?:e(?:grees|fault)|a(?:te|y))|exp|f(?:loor(?:avg)?|ormat|ield)|g(?:lob|roup_concat)|h(?:ex|our)|i(?:f(?:null)?|if|n(?:str)?)|l(?:ast(?:_insert_rowid)?|ength|ike(?:l(?:ihood|y))?|n|o(?:ad_extension|g(?:10|2)?|wer(?:pi)?|cal)|trim)|m(?:ax|in(?:ute)?|o(?:d|nth))|n(?:ullif|ow)|p(?:i|ow(?:er)?|rintf|assword)|quote|r(?:a(?:dians|ndom(?:blob)?)|e(?:p(?:lace|eat)|verse)|ound|trim|ight)|s(?:i(?:gn|nh?)|oundex|q(?:lite_(?:compileoption_(?:get|used)|offset|source_id|version)|rt)|u(?:bstr(?:ing)?|m)|econd|leep)|t(?:anh?|otal(?:_changes)?|r(?:im|unc)|ypeof|ime)|u(?:n(?:icode|likely)|(?:pp|s)er)|zeroblob|bin|v(?:alues|ersion)|week|year)[^0-9A-Z_a-z]*\\(', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(318, '942361', '(?i:^[\\W\\d]+\\s*?(?:alter|union)\\b)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(319, '942410', '(?i)\\b(?:a(?:(?:b|co)s|dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:in|cii(?:str)?)|tan2?|vg)|b(?:enchmark|i(?:n(?:_to_num)?|t_(?:and|count|length|x?or)))|c(?:ast|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|o(?:alesce|ercibility|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|(?:un)?t)|r32|ur(?:(?:dat|tim)e|rent_(?:date|time(?:stamp)?|user)))|d(?:a(?:t(?:abase|e(?:_(?:add|format|sub)|diff)?)|y(?:name|of(?:month|week|year))?)|count|e(?:code|(?:faul|s_(?:de|en)cryp)t|grees)|ump)|e(?:lt|nc(?:ode|rypt)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:eld(?:_in_set)?|nd_in_set)|loor|o(?:rmat|und_rows)|rom_(?:base64|days|unixtime))|g(?:et_(?:format|lock)|r(?:eates|oup_conca)t)|h(?:ex(?:toraw)?|our)|i(?:f(?:null)?|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)?|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull))|null)?)|l(?:ast(?:_(?:day|insert_id))?|case|e(?:(?:as|f)t|ngth)|n|o(?:ad_file|ca(?:l(?:timestamp)?|te)|g(?:10|2)?|wer)|pad|trim)|m(?:a(?:ke(?:date|_set)|ster_pos_wait|x)|d5|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:d|nth(?:name)?))|n(?:ame_const|o(?:t_in|w)|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:assword|eriod_(?:add|diff)|g_sleep|i|o(?:sition|w(?:er)?)|rocedure_analyse)|qu(?:arter|ote)|r(?:a(?:dians|nd|wto(?:hex|nhex(?:toraw)?))|e(?:lease_lock|p(?:eat|lace)|verse)|ight|o(?:und|w_count)|pad|trim)|s(?:chema|e(?:c(?:ond|_to_time)|ssion_user)|ha[12]?|ig?n|leep|oundex|pace|qrt|t(?:d(?:dev(?:_(?:po|sam)p)?)?|r(?:cmp|_to_date))|u(?:b(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|m)|ys(?:date|tem_user))|t(?:an|ime(?:diff|_(?:format|to_sec)|stamp(?:add|diff)?)?|o_(?:base64|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|ix_timestamp)|p(?:datexml|per)|ser|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|v(?:a(?:lues|r(?:iance|_(?:po|sam)p))|ersion)|we(?:ek(?:day|ofyear)?|ight_string)|xmltype|year(?:week)?)[^0-9A-Z_a-z]*?\\(', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(320, '942470', '(?i)autonomous_transaction|(?:current_use|n?varcha|tbcreato)r|db(?:a_users|ms_java)|open(?:owa_util|query|rowset)|s(?:p_(?:(?:addextendedpro|sqlexe)c|execute(?:sql)?|help|is_srvrolemember|makewebtask|oacreate|p(?:assword|repare)|replwritetovarbin)|ql_(?:longvarchar|variant))|utl_(?:file|http)|xp_(?:availablemedia|(?:cmdshel|servicecontro)l|dirtree|e(?:numdsn|xecresultset)|filelist|loginconfig|makecab|ntsec(?:_enumdomains)?|reg(?:addmultistring|delete(?:key|value)|enum(?:key|value)s|re(?:ad|movemultistring)|write)|terminate(?:_process)?)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(321, '942480', '(?i)\\b(?:(?:d(?:bms_[0-9A-Z_a-z]+\\.|elete\\b[^0-9A-Z_a-z]*?\\bfrom)|(?:group\\b.*?\\bby\\b.{1,100}?\\bhav|overlay\\b[^0-9A-Z_a-z]*?\\(.*?\\b[^0-9A-Z_a-z]*?plac)ing|in(?:ner\\b[^0-9A-Z_a-z]*?\\bjoin|sert\\b[^0-9A-Z_a-z]*?\\binto|to\\b[^0-9A-Z_a-z]*?\\b(?:dump|out)file)|load\\b[^0-9A-Z_a-z]*?\\bdata\\b.*?\\binfile|s(?:elect\\b.{1,100}?\\b(?:(?:.*?\\bdump\\b.*|(?:count|length)\\b.{1,100}?)\\bfrom|(?:data_typ|from\\b.{1,100}?\\bwher)e|instr|to(?:_(?:cha|numbe)r|p\\b.{1,100}?\\bfrom))|ys_context)|u(?:nion\\b.{1,100}?\\bselect|tl_inaddr))\\b|print\\b[^0-9A-Z_a-z]*?@@)|(?:collation[^0-9A-Z_a-z]*?\\(a|@@version|;[^0-9A-Z_a-z]*?\\b(?:drop|shutdown))\\b|\'(?:dbo|msdasql|s(?:a|qloledb))\'', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(322, '942441', '[a-zA-Z0-9_-]{61,61}', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(323, '942442', '[a-zA-Z0-9_-]{91,91}', 'pass', 0, 'none', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(324, '942440', '/\\*!?|\\*/|[\';]--|--(?:[\\s\\x0b]|[^\\-]*?-)|[^&\\-]#.*?[\\s\\x0b]|;?\\x00', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(325, '942450', '(?i:\\b0x[a-f\\d]{3,})', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(326, '942510', '(?:`(?:(?:[\\w\\s=_\\-+{}()<@]){2,29}|(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)`)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(327, '942101', 'detectSQLi', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:detectSQLi', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(328, '942152', '(?i)\\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|iel(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|t)|r32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|grees|s_(?:de|en)crypt)|ump)|e(?:lt|n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|object(?:_(?:agg|keys))?|e(?:ac|xtract_pat)h(?:_text)?|insert|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|inser_id)|case|e(?:as|f)t|i(?:kel(?:ihood|y)|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2)|wer)|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:(?:lyg|siti)on|w)|rocedure_analyse)|qu(?:arter|ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|pace|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp)|likely)|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\\(', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(329, '942321', '(?i)create[\\s\\x0b]+(?:function|procedure)[\\s\\x0b]*?[0-9A-Z_a-z]+[\\s\\x0b]*?\\([\\s\\x0b]*?\\)[\\s\\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\\s\\x0b]*?[0-9A-Z_a-z]+|iv[\\s\\x0b]*?\\([\\+\\-]*[\\s\\x0b\\.0-9]+,[\\+\\-]*[\\s\\x0b\\.0-9]+\\))|exec[\\s\\x0b]*?\\([\\s\\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\\s\\x0b]+analyse)[\\s\\x0b]*?\\(|;[\\s\\x0b]*?(?:declare|open)[\\s\\x0b]+[\\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\\s\\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(330, '942015', '3', 'pass', 0, '', 2, 3, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(331, '942016', '3', 'pass', 0, '', 2, 3, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(332, '942251', '(?i)\\W+\\d*?\\s*?\\bhaving\\b\\s*?[^\\s\\-]', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(333, '942460', '\\W{4}', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(334, '942511', '(?:\'(?:(?:[\\w\\s=_\\-+{}()<@]){2,29}|(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)\')', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(335, '942530', '\';', 'pass', 0, '', 2, 0, 'NOTICE', 'attack-sqli', 2, 'operator:rx', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(336, '942017', '4', 'pass', 0, '', 2, 4, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(337, '942018', '4', 'pass', 0, '', 2, 4, 'NOTICE', 'attack-sqli', 2, 'operator:lt', 'teckglobal_bfp/1.2.0', 0, '0', '', '', 1, 0),
(338, 'END-REQUEST-942-APPLICATION-ATTACK-SQLI', '', 'pass', 0, '', 2, 0, 'NOTICE', 'exception', 2, '', 'teckglobal_bfp/1.2.0', 0, '0', '', 'End of rule set', 1, 0);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `1bigdickteckglobal_bfp_waf_test`
--
ALTER TABLE `1bigdickteckglobal_bfp_waf_test`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_enabled_phase_paranoia` (`enabled`,`phase`,`paranoia_level`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `1bigdickteckglobal_bfp_waf_test`
--
ALTER TABLE `1bigdickteckglobal_bfp_waf_test`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=339;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
