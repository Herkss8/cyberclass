-- Read-only export of the complete question bank.
SELECT id, group_key, topic, data, position
FROM public.questions
ORDER BY group_key, topic, position, id;
