// Your tour guide asked you a really intriguing question. You can't get
// embarrassed in front of everyone, can you?

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#define FREE(x)                                                                \
  {                                                                            \
    free(x);                                                                   \
    x = NULL;                                                                  \
  }

#define WAIT_KEY                                                               \
  {                                                                            \
    int __c;                                                                   \
    while ((__c = getchar()) != '\n' && __c != EOF)                            \
      ;                                                                        \
  }

typedef struct {
  uint32_t difficulty;
  uint32_t answer;
} question_t;

typedef struct {
  uint32_t attempt;
  uint32_t answer;
} answer_t;

int was_close = 0;
const char *question_title =
    "How many tourists came to Prague only last year?";

question_t *generate_question() {
  question_t *question = (question_t *)malloc(sizeof(question_t));

  question->difficulty = 100;
  question->answer = 10 + rand() * 500000;

  return question;
}

answer_t *ask_question(uint8_t attempt, question_t *question) {
  printf("%s\n", question_title);

  int response;
  scanf("%d", &response);

  if (response == 0) {
    FREE(question);

    printf("I'm curious, what would you have guessed?\n");

    answer_t *answer = (answer_t *)malloc(sizeof(answer_t));
    answer->attempt = attempt;
    scanf("%d", &answer->answer);

    was_close = 1;

    return NULL;
  }

  answer_t *answer = (answer_t *)malloc(sizeof(answer_t));
  answer->attempt = attempt;
  answer->answer = response;

  return answer;
}

char *verify_answer(question_t *question, answer_t *answer) {
  if (question == NULL || answer == NULL)
    return NULL;

  if (question->answer == answer->answer) {
    printf("You win!\n");

    FILE *fptr;

    fptr = fopen("flag.txt", "r");
    char *content = (char *)malloc(200 * sizeof(char));

    fgets(content, 200, fptr);

    return content;
  }

  return NULL;
}

int main() {
  setbuf(stdout, NULL);
  srand((unsigned int)time(NULL));

  printf("Are you ready for your final question? Everyone's looking! ");
  WAIT_KEY;

  question_t *question = generate_question();
  int attempt = 0;

  while (attempt < 2) {
    answer_t *answer = ask_question(attempt++, question);

    if (answer != NULL) {
      const char *flag = verify_answer(question, answer);

      if (flag != NULL) {
        printf("%s\n", flag);

        return 0;
      }
    }

    if (attempt != 2) {
      if (was_close) {
        printf("So close! I give you one last chance.\n");
        WAIT_KEY;
      } else {
        printf("Attempt %d, I give you one last chance.\n", attempt);
        WAIT_KEY;
      }
    }
  }

  printf("Sorry, you have used all you guesses...\n");

  return 0;
}