import copy
import unittest

from example import canonical, checksum, create, fixtures, local_sender, run, verify


class DossierTest(unittest.TestCase):
    def test_end_to_end(self):
        data=create(); self.assertTrue(verify(data,checksum(canonical(data))))
        self.assertEqual(data["before"]["proof"]["size"],2)
        self.assertEqual(data["after"]["proof"]["size"],3)
        self.assertEqual(data["before"]["decisions"]['["undated-hour",1]']["decision"],"indeterminate")
        self.assertEqual(data["before"]["decisions"]['["bulletin",2]']["decision"],"ineligible")
        self.assertNotEqual(data["before"]["selected_root"],data["after"]["selected_root"])
        for key in ("before","after"):
            self.assertNotIn("undated-hour",data[key]["request_utf8"])

    def test_capture_observes_bytes(self):
        observed=[]
        def sender(request):
            observed.append(request)
            return local_sender(request)
        item=run(fixtures(),"2026-06-01T12:00:00+02:00",sender)
        self.assertEqual(observed,[item["request_utf8"].encode()])

    def test_revalidation_detects_changes(self):
        data=create(); pin=checksum(canonical(data))
        for key,value in (("output","forged"),("selected_root","0"*64),("request_utf8","{}"),
                          ("disclosed_leaf_utf8","other"),("decisions",{})):
            copy_data=copy.deepcopy(data);copy_data["before"][key]=value
            with self.assertRaises(ValueError):verify(copy_data,pin)
            with self.assertRaises(ValueError):verify(copy_data,checksum(canonical(copy_data)))
        data["source_pool"][0]["text"]+="!"
        with self.assertRaises(ValueError): verify(data,checksum(canonical(data)))
