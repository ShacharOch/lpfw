#include "gtest/gtest.h"
#include "ruleslist.h"
#include <fstream>

//creates dirs recursively up until the last dir in the path
static void _mkdir(const char *dir) {
        char tmp[256];
        char *p = NULL;
        size_t len;

        snprintf(tmp, sizeof(tmp),"%s",dir);
        len = strlen(tmp);
        if(tmp[len - 1] == '/')
                tmp[len - 1] = 0;
        for(p = tmp + 1; *p; p++)
                if(*p == '/') {
                        *p = 0;
                        mkdir(tmp, S_IRWXU);
                        *p = '/';
                }
        mkdir(tmp, S_IRWXU);
}


class RulesListFriend
{
public:
  void setPathToProc(RulesList*, string  );
  void setRules(RulesList*, vector<rule>);
};
//allows to set rules directly for the test fixture.
//Otherwise we'd have to use add/modify/mark_active etc to set rules
//But since we aren't supposed to use those methods to set rules because we are testing them
//the workaround is to set rules manually
void RulesListFriend::setRules(RulesList* parent, vector<rule> newrules){
  parent->rules = newrules;
}
void RulesListFriend::setPathToProc(RulesList* parent, string newpath){
  parent->path_to_proc = newpath;
}


class RulesListTest: public ::testing::Test{
public:
  //Create a list of various rules by changing the rules var directly
  RulesListFriend f;
  RulesList* rulesList;
  rule rule1;
  rule rule2;
  rule rule3a;
  rule rule3b;
  rule rule5;
  vector<rule> init_rules;
  RulesListTest(){
    rule1.path = "/rule1/path";
    rule1.perms = ALLOW_ALWAYS;
    rule1.sha = "rule1sha";
    rule1.is_fixed_ctmark = true;
    rule1.ctmark_out = 7777;
    rule1.ctmark_in = 17777;

    rule2.path = "/rule2/path";
    rule2.perms = DENY_ALWAYS;
    rule2.sha = "rule2sha";
    rule2.is_fixed_ctmark = false;

    //two similar rules which are removed with remove(pid = 'all')
    rule3a.path = "/rule3/path";
    rule3a.perms = ALLOW_ALWAYS;
    rule3a.sha = "rule3sha";
    rule3a.is_active = true;
    rule3a.ctmark_out = 27777;
    rule3a.ctmark_in = 37777;

    rule3b.path = "/rule3/path";
    rule3b.perms = ALLOW_ALWAYS;
    rule3b.sha = "rule3sha";
    rule3b.is_active = true;
    rule3b.ctmark_out = 47777;
    rule3b.ctmark_in = 57777;

    //an active rule which will be remove()d
    rule5.path = "/rule5/path";
    rule5.perms = ALLOW_ALWAYS;
    rule5.pid = "11223";
    rule5.sha = "rule5sha";
    rule5.is_active = true;
    rule5.ctmark_out = 44444;
    rule5.ctmark_in = 54444;

    init_rules.push_back(rule1);
    init_rules.push_back(rule2);
    init_rules.push_back(rule3a);
    init_rules.push_back(rule3b);
    init_rules.push_back(rule5);
    vector<rule> empty;
    rulesList = new RulesList(empty);
    f.setPathToProc(rulesList, "/tmp/");
    f.setRules(rulesList, init_rules);
  }
};


//only using fixture to get rule1 rule2
TEST_F(RulesListTest, constructor){
  vector<rule> r {rule1, rule2};
  RulesList rl(r);
  vector<rule> rulescopy = rl.get_rules_copy();
  ASSERT_EQ(rulescopy.size(), 2);
  for (int i = 0; i < rulescopy.size(); i++){
    ASSERT_NE(rulescopy[i].ctmark_out, 0);
    ASSERT_NE(rulescopy[i].ctmark_in, 0);
    ASSERT_EQ(rulescopy[i].uid == "", false);
  }
}

TEST_F(RulesListTest, add){
  string new1path = "/tmp/new1";
  string new1hash = "2AC8A140BD002C6D2F46A980AEAD578B14D1F36978ABD34825787681FD7E091F";
  ofstream f(new1path);
  f << "rule3";
  f.close();
  _mkdir("/tmp/3333/fd");

  string new2path = "/rule4";
  string new2pid = "19203";
  string new2perms = ALLOW_ALWAYS;
  bool new2is_active = true;
  string new2sha = "DEADBEEF";
  unsigned long long new2stime = 1234567;
  u_int32_t new2ctmark = 15243;

  //should fail because path is non-existent and ALLOW_ONCE
  ruleslist_rv rv1 = rulesList->add("/fail", "1", ALLOW_ONCE, true, "", 123456, 0, true);
  ASSERT_EQ(rv1.success, false);
  //check later that pidfdpath is set correctly and dirstream is NULL and sha is set and ctmark is set
  ruleslist_rv rv2 = rulesList->add(new2path, new2pid, new2perms, new2is_active,
                                   new2sha, new2stime, new2ctmark, true);
  ASSERT_EQ(rv2.success, true);
  //check later that hashing gave correct result and that ctmarks are assigned
  ruleslist_rv rv3 = rulesList->add(new1path, "3333", ALLOW_ONCE, true, "", 123456, 0, true);
  ASSERT_EQ(rv3.success, true);
  //a duplicate rule must be rejected
  ruleslist_rv rv4 = rulesList->add(new1path, "3333", DENY_ONCE, false, "", 123456, 0, true);
  ASSERT_EQ(rv4.success, false);

  vector<rule> copy = rulesList->get_rules_copy();
  ASSERT_EQ(copy.size(), init_rules.size() + 2);
  bool bnew1Found = false;
  bool bnew2Found = false;
  for (int i=0; i < copy.size(); i++){
    if (! bnew1Found && copy[i].path == new1path){
      bnew1Found = true;
      ASSERT_EQ(copy[i].sha == new1hash, true);
      ASSERT_EQ(copy[i].ctmark_out > 0, true);
      ASSERT_EQ(copy[i].ctmark_in > 0, true);
      ASSERT_EQ(copy[i].ctmark_in - copy[i].ctmark_out == CTMARK_DELTA, true);
      continue;
    }
    else if (! bnew2Found && copy[i].path == new2path){
      bnew2Found = true;
      ASSERT_EQ(copy[i].pid == new2pid, true);
      ASSERT_EQ(copy[i].perms == new2perms, true);
      ASSERT_EQ(copy[i].is_active == new2is_active, true);
      ASSERT_EQ(copy[i].sha == new2sha, true);
      ASSERT_EQ(copy[i].stime == new2stime, true);
      ASSERT_EQ(copy[i].ctmark_out == new2ctmark, true);
      ASSERT_EQ(copy[i].ctmark_in - copy[i].ctmark_out == CTMARK_DELTA, true);
      ASSERT_EQ(copy[i].is_fixed_ctmark, false);
      ASSERT_EQ(copy[i].pidfdpath == ("/tmp/" + new2pid + "/fd/"), true);
      ASSERT_EQ(copy[i].dirstream == NULL, true);
    }
  }
  ASSERT_EQ(bnew1Found && bnew2Found, true);
}


TEST_F(RulesListTest, markActive){
  ruleslist_rv rv1;
  //mark a non-existant rule
  rv1 = rulesList->mark_active("/rule1/void", "0", 9999);
  ASSERT_EQ(rv1.success, false);
  //mark a rule with no proc//fd dir
  ruleslist_rv rv2;
  rv2 = rulesList->mark_active(rule1.path, "777", 9999);
  ASSERT_EQ(rv2.success, false);
  //mark a correct rule
  _mkdir("/tmp/3456/fd");
  ruleslist_rv rv3;
  rv3 = rulesList->mark_active(rule1.path, "3456", 9999);
  ASSERT_EQ(rv3.success, true);
  ASSERT_EQ(rv3.ctmark, rule1.ctmark_out);
  //mark an already active process
  ruleslist_rv rv4;
  rv4 = rulesList->mark_active(rule1.path, "34567", 19999);
  ASSERT_EQ(rv4.success, false);
}


TEST_F(RulesListTest, remove){
  //pass incorrect permission
  ruleslist_rv rv5;
  rv5 = rulesList->remove(rule1.path, "3456", DENY_ALWAYS);
  ASSERT_EQ(rv5.success, false);

  //pass non-existant rule
  ruleslist_rv rv6;
  rv6 = rulesList->remove("/rule1/pathnonexistant", "0", DENY_ALWAYS);
  ASSERT_EQ(rv6.success, false);

  //remove rule marked active
  ruleslist_rv rv7;
  rv7 = rulesList->remove(rule5.path, rule5.perms, rule5.pid);
  ASSERT_EQ(rv7.success, true);
  ASSERT_EQ(rv7.ctmarks_to_delete.size(), 1);
  ctmarks c = rv7.ctmarks_to_delete[0];
  ASSERT_EQ(c.in == rule5.ctmark_in && c.out == rule5.ctmark_out, true);

  //remove "all" rule
  ruleslist_rv rv8;
  rv8 = rulesList->remove(rule3a.path, rule3a.perms, "all");
  ASSERT_EQ(rv8.success, true);
  ASSERT_EQ(rv8.ctmarks_to_delete.size(), 2);
  ASSERT_EQ(rulesList->get_rules_copy().size(), init_rules.size()-3);
}

TEST_F(RulesListTest, markInactive){
  ruleslist_rv rv1;
  //mark a non-existant path
  rv1 = rulesList->mark_inactive("/rule1/void", "0");
  ASSERT_EQ(rv1.success, false);

  //mark existing path but a non-existant pid
  rv1 = rulesList->mark_inactive("/rule1/path", "1");
  ASSERT_EQ(rv1.success, false);

  //mark a correct rule
  ruleslist_rv rv3;
  rv3 = rulesList->mark_inactive(rule5.path, rule5.pid);
  ASSERT_EQ(rv3.success, true);

  //check that the rule was marked correctly
  vector<rule> r = rulesList->get_rules_copy();
  bool bFoundCorrectRule = false;
  for (int i=0; i < r.size(); i++){
    if (r[i].path != rule5.path) continue;
    ASSERT_EQ(r[i].pid == "0", true);
    ASSERT_EQ(r[i].is_active == false, true);
    ASSERT_EQ(r[i].ctmark_in >= CTMARKIN_BASE, true);
    ASSERT_EQ(r[i].ctmark_out >= CTMARKOUT_BASE, true);
    bFoundCorrectRule = true;
  }
  ASSERT_EQ(bFoundCorrectRule, true);
}
