-- Synthetic users for the public portfolio version of the lab.
-- Password values are SHA-256 hashes retained for compatibility with the
-- original coursework application. They are lab fixtures, not real accounts.

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `uid` varchar(64) NOT NULL DEFAULT '',
  `lastname` varchar(64) NOT NULL DEFAULT '',
  `firstname` varchar(64) NOT NULL DEFAULT '',
  `email` varchar(64) NOT NULL DEFAULT '',
  `pwd` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`uid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

INSERT INTO `users` VALUES
  ('ps', 'Researcher', 'Alex', 'alex.researcher@example.test', '8361e17ebad9927c731c69fc556d813487096e066d713fd5b20d4214fad1f4e1'),
  ('lb', 'Builder', 'Blake', 'blake.builder@example.test', '19c7f5e93fa8b9890c49d932cc55f1b037748474dbf5bf75b6bf47746f763e31'),
  ('ms', 'Scientist', 'Morgan', 'morgan.scientist@example.test', '99b51b0c4a78be249dfcc7cd2bd0e10039aaa2cbaf69101b3a01f774262db580'),
  ('a3', 'Analyst', 'Avery', 'avery.analyst@example.test', '86c337f6a005a35e0880984d6383afe3a26c3db0f429440b3ccb670c4a2d56d7');
