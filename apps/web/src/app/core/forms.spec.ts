import { buildInput, emptyModel, labeledLines, modelFromView, tags } from './forms';
import { ItemView } from './types';

describe('form mapping', () => {
  it('parses labeled lines and tags', () => {
    expect(labeledLines('work | a@example.test\n\n b@example.test ')).toEqual([
      { label: 'work', value: 'a@example.test' },
      { label: null, value: 'b@example.test' },
    ]);
    expect(tags(' a, ,b ')).toEqual(['a', 'b']);
  });

  it('create: empty secrets are absent, values are set', () => {
    const m = { ...emptyModel(), title: ' T ', password: 'pw', urls: 'https://x.test\n' };
    const input = buildInput('login', m, false);
    expect(input.title).toBe('T');
    expect(input.notes).toBeNull();
    expect(input.data).toMatchObject({ kind: 'login', password: 'pw', urls: ['https://x.test'], recovery_codes: [] });
  });

  it('edit: empty secret keeps, clear checkbox removes, text replaces', () => {
    const keep = buildInput('login', { ...emptyModel(), title: 't' }, true);
    expect(keep.data).toMatchObject({ password: null, recovery_codes: null });
    expect(keep.notes).toBeNull();
    const clear = buildInput('login', { ...emptyModel(), title: 't', clear: { password: true, notes: true } }, true);
    expect(clear.data).toMatchObject({ password: '' });
    expect(clear.notes).toBe('');
    const wallet = buildInput('crypto_wallet', { ...emptyModel(), title: 't', recoveryPhrase: 'new words' }, true);
    expect(wallet.data).toMatchObject({ recovery_phrase: 'new words', wallet_password: null });
  });

  it('edit: stored concealed custom field with empty value is kept by index', () => {
    const m = {
      ...emptyModel(),
      title: 't',
      custom: [
        { label: 'pin', concealed: true, value: '', existing: 0 },
        { label: 'plan', concealed: false, value: 'basic', existing: 1 },
        { label: '', concealed: false, value: 'ignored', existing: null },
      ],
    };
    expect(buildInput('secure_note', m, true).custom_fields).toEqual([
      { label: 'pin', concealed: true, value: null, existing: 0 },
      { label: 'plan', concealed: false, value: 'basic', existing: 1 },
    ]);
  });

  it('prefills edit form from a secret-free view without secrets', () => {
    const v: ItemView = {
      id: 'x', kind: 'contact', rev: 1, title: 'C', tags: ['a'], created_at: 0, updated_at: 0, imported: false,
      data: { full_name: 'Ada', organization: null, emails: [{ label: 'w', value: 'a@x.test' }], phones: [], addresses: [], websites: [] },
      secrets: [{ key: 'notes', label: 'Notes' }],
      custom_fields: [{ index: 0, label: 'pin', section: null, concealed: true, value: null }],
    };
    const m = modelFromView(v);
    expect(m.fullName).toBe('Ada');
    expect(m.emails).toBe('w | a@x.test');
    expect(m.notes).toBe('');
    expect(m.custom[0]).toEqual({ label: 'pin', concealed: true, value: '', existing: 0 });
  });
});
