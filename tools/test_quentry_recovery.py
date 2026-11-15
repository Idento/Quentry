"""
Tests de l'outil de récupération (format 2.3 du 15/11/2026 : la corbeille voyage dans la
sauvegarde). Lancer : python -m unittest tools/test_quentry_recovery.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import quentry_recovery as qr  # noqa: E402


class SaveTrashTests(unittest.TestCase):
    def test_corbeille_sortie_dans_son_propre_dossier(self):
        data = {
            'entries': [],
            'trash': [{
                'id': 't1', 'createdAt': '2026-10-01T08:00:00.000Z', 'content': '<p>Note supprimee</p>',
                'category': 'pro', 'deletedAt': '2026-11-10T08:00:00.000Z',
            }],
        }
        with tempfile.TemporaryDirectory() as out:
            count = qr.save_trash(data, out)
            self.assertEqual(count, 1)
            with open(os.path.join(out, 'corbeille', 'trash.json'), encoding='utf-8') as f:
                self.assertEqual(json.load(f), data['trash'])
            txts = [n for n in os.listdir(os.path.join(out, 'corbeille')) if n.endswith('.txt')]
            self.assertEqual(len(txts), 1)
            with open(os.path.join(out, 'corbeille', txts[0]), encoding='utf-8') as f:
                text = f.read()
            self.assertIn('Deleted: 2026-11-10T08:00:00.000Z', text)
            self.assertIn('<p>Note supprimee</p>', text)

    def test_ancien_fichier_sans_corbeille_rien_cree(self):
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(qr.save_trash({'entries': []}, out), 0)
            self.assertFalse(os.path.exists(os.path.join(out, 'corbeille')))

    def test_entree_abimee_ignoree(self):
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(qr.save_trash({'trash': [None, 'x', {'id': 'y'}]}, out), 0)


if __name__ == '__main__':
    unittest.main()
