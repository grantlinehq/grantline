import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { EntityLabel, EvidenceList } from '../.test-output/components.js';

// Benign markup canaries exercise the actual provider-text render paths.
// No script or executable payload is needed to verify escaping.
const name = '<b>literal metadata & "quotes"</b>';
const entity = { id:'fixture', kind:'service_account', name, native_id:'fixture-uid', source_id:'fixture', scope:'fixture', observed_at:'2026-09-26T00:00:00Z', provenance:'synthetic_fixture', attributes:{},field_status:{} };
const label = renderToStaticMarkup(createElement(EntityLabel,{entity,onClick(){}}));
assert(label.includes('&lt;b&gt;literal metadata &amp; &quot;quotes&quot;&lt;/b&gt;'));
assert(!label.includes('<b>'));
const evidence = renderToStaticMarkup(createElement(EvidenceList,{ids:['fixture'],evidence:[{id:'fixture',source_id:'fixture',native_id:name,locator:'literal/<b>metadata</b>',fields:[name],observed_at:entity.observed_at,assertion_kind:'declared'}]}));
assert(evidence.includes('literal/&lt;b&gt;metadata&lt;/b&gt;'));
assert(!evidence.includes('<b>'));
console.log('Provider name, native ID, locator and field markup render as escaped text.');
