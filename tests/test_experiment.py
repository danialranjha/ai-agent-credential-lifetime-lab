import unittest
import experiment as e

class LifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=e.run()
        cls.rows={(r['scenario'],r['method']):r for r in cls.data['rows']}
    def row(self,name,method):
        return self.rows[name,method]
    def test_late_path_distinction(self):
        for mode in ('644','600'):
            a=self.row('after_'+mode,'persistent');b=self.row('after_'+mode,'read_then_delete')
            self.assertEqual(a['reader']['value'],e.MARKER)
            self.assertEqual(b['reader']['status'],'missing')
            self.assertFalse(b['path_exists_after'])
            self.assertTrue(a['path_exists_after'])
            self.assertEqual(a['consumer']['value'],b['consumer']['value'])
            self.assertEqual(b['consumer']['value'],e.MARKER)
    def test_owned_0600_still_readable_before(self):
        for method in e.METHODS:
            r=self.row('before_600',method)
            self.assertEqual(r['mode_at_start'],'0o600')
            self.assertEqual(r['reader']['value'],e.MARKER)
    def test_held_descriptor_survives_unlink(self):
        for mode in ('644','600'):
            r=self.row('held_descriptor_'+mode,'read_then_delete')
            self.assertFalse(r['path_exists_after'])
            self.assertEqual(r['reader']['value'],e.MARKER)
    def test_benign_work_file(self):
        for method in e.METHODS:
            self.assertEqual(self.row('ordinary_file',method)['reader']['value'],e.NOTE)
    def test_missing_exit_zero_is_not_read_success(self):
        a=self.row('missing','persistent');b=self.row('missing','read_then_delete')
        self.assertEqual(a['consumer'],{'value':'','exit_status':1})
        self.assertEqual(b['consumer'],{'value':'','exit_status':0})
        self.assertEqual(b['reader']['status'],'missing')
    def test_second_consumer_exposes_cache_requirement(self):
        self.assertEqual(self.row('second_consumer','persistent')['second_consumer']['value'],e.MARKER)
        self.assertEqual(self.row('second_consumer','read_then_delete')['second_consumer'],{'value':'','exit_status':0})
    def test_same_user_and_replaced_environment(self):
        for r in self.data['rows']:
            self.assertTrue(r['reader']['same_user'])
            self.assertFalse(r['reader']['environment_has_marker'])
    def test_expected_modes_and_consumer_values(self):
        self.assertEqual(len(self.data['rows']),18)
        for r in self.data['rows']:
            if r['scenario']!='missing':
                self.assertEqual(r['consumer']['value'],e.MARKER)
                self.assertIn(r['mode_at_start'],['0o644','0o600'])
    def test_faults_change_critical_observations(self):
        keep=e.run_case('after_600','after',0o600,'read_then_delete',fault='keep_file')
        self.assertNotEqual(keep['reader']['status'],'missing')
        deny=e.run_case('ordinary_file','ordinary_file',0o600,'read_then_delete',fault='deny_all')
        self.assertNotEqual(deny['reader']['value'],e.NOTE)
    def test_repeatability(self):
        self.assertEqual(self.data,e.run())

if __name__=='__main__':unittest.main()
