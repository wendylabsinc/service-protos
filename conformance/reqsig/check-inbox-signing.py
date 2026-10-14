#!/usr/bin/env python3
"""Check the compiled inbox/APNs signing boundary, not runtime verification.

Usage: check-inbox-signing.py current-descriptor.json base-descriptor.json
Descriptors: buf build --as-file-descriptor-set --exclude-source-info -o FILE.json
"""

import copy
import json
from pathlib import Path
import re
import sys
import unittest


SIGNED_INPUT = ".wendycloud.v2.SignedRequest"
SIGNED_OPTION = "[wendy.signed_request]"
SCOPE = {
    "wendycloud/v2/notifications.proto": {
        "ListNotificationsV2": "ListNotificationsV2Request",
        "GetNotification": "GetNotificationRequest",
        "CountNotifications": "CountNotificationsRequest",
        "DeleteNotifications": "DeleteNotificationsRequest",
        "DeleteNotificationsThrough": "DeleteNotificationsThroughRequest",
        "SetNotificationReadStatus": "SetNotificationReadStatusRequest",
        "SetNotificationReadStatusThrough": "SetNotificationReadStatusThroughRequest",
    },
    "wendycloud/v2/apns.proto": {
        "RegisterDeviceToken": "APNSRegisterDeviceTokenRequest",
        "UnregisterDeviceToken": "APNSUnregisterDeviceTokenRequest",
    },
}


def files(path):
    return {file["name"]: file for file in json.loads(Path(path).read_text())["file"]}


def methods(file):
    return {
        (service["name"], method["name"]): method
        for service in file.get("service", [])
        for method in service.get("method", [])
    }


def require_signed(method):
    if method["inputType"] != SIGNED_INPUT:
        raise AssertionError(f'{method["name"]}: bare input')
    if method.get("options", {}).get(SIGNED_OPTION) is not True:
        raise AssertionError(f'{method["name"]}: missing signing annotation')
    if method.get("clientStreaming", False) or method.get("serverStreaming", False):
        raise AssertionError(f'{method["name"]}: unexpected streaming change')


class InboxSigning(unittest.TestCase):
    def test_compiled_inputs_annotations_and_payload_messages(self):
        for path, scope in SCOPE.items():
            file = CURRENT[path]
            payloads = {message["name"] for message in file["messageType"]}
            found = set()
            for (_, name), method in methods(file).items():
                if name in scope:
                    with self.subTest(method=name):
                        require_signed(method)
                        self.assertIn(scope[name], payloads)
                    found.add(name)
                # The existing CreateNotification remains signed too. No
                # method may advertise signing with a bare payload input.
                with self.subTest(agreement=name):
                    self.assertEqual(
                        method["inputType"] == SIGNED_INPUT,
                        method.get("options", {}).get(SIGNED_OPTION, False),
                    )
            self.assertEqual(found, set(scope))

    def test_payload_type_comments_name_the_preserved_message(self):
        root = Path(__file__).resolve().parents[2]
        for path, scope in SCOPE.items():
            source = (root / path).read_text()
            for name, payload in scope.items():
                with self.subTest(method=name):
                    self.assertRegex(
                        source,
                        re.escape(f'// Signed; payload_type "wendycloud.v2.{payload}".')
                        + r"\s+rpc " + re.escape(name) + r"\(SignedRequest\)",
                    )

    def test_migration_preserves_messages_and_other_method_contracts(self):
        for path, scope in SCOPE.items():
            before, after = BASE[path], CURRENT[path]
            old_methods, new_methods = methods(before), methods(after)
            migrating = any(
                method["inputType"] != SIGNED_INPUT
                for (_, name), method in old_methods.items() if name in scope
            )
            for key, old in old_methods.items():
                name = key[1]
                with self.subTest(method=name):
                    new = new_methods[key]
                    if name in scope:
                        expected = copy.deepcopy(old)
                        expected["inputType"] = SIGNED_INPUT
                        expected.setdefault("options", {})[SIGNED_OPTION] = True
                        self.assertEqual(new, expected)
                        if old["inputType"] != SIGNED_INPUT:
                            self.assertEqual(old["inputType"], ".wendycloud.v2." + scope[name])
                    else:
                        # Keep the file-scoped Buf exception from masking an
                        # input-type change to any other existing method.
                        self.assertEqual(new["inputType"], old["inputType"])
                        if migrating:
                            self.assertEqual(new, old)
            if migrating:
                self.assertEqual(set(new_methods), set(old_methods))
                self.assertEqual(after.get("messageType"), before.get("messageType"))
                self.assertEqual(after.get("enumType"), before.get("enumType"))

    def test_guard_rejects_bare_inputs_and_missing_annotations(self):
        method = next(m for m in methods(CURRENT["wendycloud/v2/apns.proto"]).values()
                      if m["name"] == "RegisterDeviceToken")
        bare = copy.deepcopy(method)
        bare["inputType"] = ".wendycloud.v2.APNSRegisterDeviceTokenRequest"
        with self.assertRaises(AssertionError):
            require_signed(bare)
        unmarked = copy.deepcopy(method)
        unmarked.get("options", {}).pop(SIGNED_OPTION, None)
        with self.assertRaises(AssertionError):
            require_signed(unmarked)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    CURRENT, BASE = files(sys.argv[1]), files(sys.argv[2])
    unittest.main(argv=[sys.argv[0]], verbosity=2)
