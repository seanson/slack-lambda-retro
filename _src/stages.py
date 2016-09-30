ITEM_STAGES = ['What went well?', 'What could have gone better?', 'What was confusing?']
RETRO_STAGES = ['STARTED', ] + ITEM_STAGES + ['RESULTS', 'ACTIONS', 'STOPPED']

STAGE_MESSAGES = {'STARTED': """@here: A new retrospective for this channel has begun.
This retro will have five distinct states:
'What Went Right',
'What Can We Improve',
'What Was Confusing',
Voting,
Actions.
---
As of this point, anything said in this channel will be picked up as an item in this retro.
As I read items, I will mark them with a :thumbsup:
---
Each person is allowed to vote up to three times for items in the entire retro.
You may vote by adding your :thumbsup: to any item that comes up.
At the end of the session I will tally up the votes and ensure each person has only voted three times.
---
When all the votes are tallied, I will announce the top 5 items by vote count.
Each of the top items will then be presented again, one at a time, so that actions can be associated with them.
When this has finished, I will upload a copy of the resulting retro to Slack for the team!
---
Finally, remember that the objective of this tool is to allow your team to provide transparent feedback and improve.
The underlying focus must be the assumption that all people in the team are working to the best of their ability in \
the situations at hand.
You may advance each stage with the retro command: `/retro next`
Have fun!""",

                  ITEM_STAGES[0]: """Welcome to the first stage of the retrospective!
Our first look will be at 'What went well?'.
This can refer to things as simple as standup attendance, group coffee events or more complicated items such as a \
particular feature launching or a difficult architecture decision that was reached.
""",
                  ITEM_STAGES[1]: """Welcome to the next stage of the retrospective!
Our second look will be at 'What could have gone better?'.
The goal of this is not blame. Valuable suggestions in this area can be where you felt frustration dealing with \
internal discussions or other groups, patterns you have noticed that cause issues, or anything else that needs \
improvement.
""",
                  ITEM_STAGES[2]: """Welcome to the penultimate stage of the retrospective!
This look will be at 'What was confusing?'.
Items in this stage should be about what caused confusion for you in this iteration. Often used examples are \
things like processes or escalations that are lacking clarity, technological directions that are lacking, \
questions about value in certain rituals.""",
                  'RESULTS': """ We will now see the results of the voting below.""",
                  'ACTIONS': """ Welcome to the final stage of the retrospective!
Here we are looking to collect actions that we can take away to address the top voted ideas.  For what went well, this \
refers to how we can keep these beneficial actions going.
For what needs work, it's what we can do to improve the processes involved.
For what was confusing, it's what we can do to further clarify the systems and processes for the future!""",
                  'STOPPED': """ Thank you for joining us in the retrospective! The items listed will be compiled \
together with the actions for a full retrospective plan."""
                  }
