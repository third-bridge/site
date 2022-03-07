;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.v3.authorization-explainer-test
  (:require
   [clojure.test :refer [deftest is are testing use-fixtures] :as t]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*]]
   [xtdb.api :as xt]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(use-fixtures :each with-xt)

;; As a warmup, let's start with some contrived data and demonstrate how
;; authorization works in Site.

;; In Site's authorization system, a subject might cause an action on a resource
;; (which might cause it to change in some way). The authorization system must
;; first check that the subject (user) is allowed to cause a given action on the
;; resource.

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/actions/resources.

;; Note: if you're not familiar with the Alice and Bob characters, see
;; https://en.wikipedia.org/wiki/Alice_and_Bob#Cast_of_characters

(defn check-permissions
  "Given a subject, possible actions and resource, return all related pairs of permissions and actions."
  [db subject actions resource rules]
  (xt/q
   db
   {:find '[(pull permission [*]) (pull action [*])]
    :keys '[permission action]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [(contains? actions action)]
      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions resource]}

   subject actions resource))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db subject actions rules]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [(contains? actions action)]

      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions]}

   subject actions))

(defn allowed-subjects
  "Given a resource and a set of actions, which subjects can access and via which
  actions?"
  [db resource actions rules]
  (->> (xt/q
        db
        {:find '[subject action]
         :keys '[subject action]
         :where
         '[
           [permission ::site/type "Permission"]
           [action ::site/type "Action"]
           [permission ::pass/action action]
           [(contains? actions action)]

           (allowed? permission subject action resource)]

         :rules rules

         :in '[resource actions]}

        resource actions)))

(defn pull-allowed-resource
  "Given a subject, a set of possible actions and a resource, pull the allowed
  attributes."
  [db subject actions resource rules]
  (let [check-result (check-permissions db subject actions resource rules)
        pull-expr (vec (mapcat
                        (fn [{:keys [action]}]
                          (::pass/pull action))
                        check-result))]
    (xt/pull db pull-expr resource)))

(defn pull-allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db subject actions rules]
  (let [results
        (xt/q
         db
         {:find '[resource (pull action [::xt/id ::pass/pull]) permission]
          :keys '[resource action permission]
          :where
          '[
            [permission ::site/type "Permission"]
            [action ::site/type "Action"]
            [permission ::pass/action action]
            [(contains? actions action)]

            (allowed? permission subject action resource)]

          :rules rules

          :in '[subject actions]}

         subject actions)
        pull-expr (vec (mapcat (comp ::pass/pull :action) results))]

    (->> results
         (map :resource)
         (xt/pull-many db pull-expr))))

(def ALICE
  {:xt/id "https://example.org/people/alice",
   ::site/type "User"
   ::username "alice"})

(def BOB
  {:xt/id "https://example.org/people/bob",
   ::site/type "User"
   ::username "bob"})

(def CARLOS
  {:xt/id "https://example.org/people/carl",
   ::site/type "User"
   ::username "carl"})

(def FAYTHE
  {:xt/id "https://example.org/people/faythe",
   ::site/type "User"
   ::username "faythe"})

(def OSCAR
  {:xt/id "https://example.org/people/oscar",
   ::site/type "User"
   ::username "oscar"})

(def ALICE_USER_DIR_PRIVATE_FILE
  {:xt/id "https://example.org/~alice/private.txt"
   ::site/type "Resource"})

(def ALICE_USER_DIR_SHARED_FILE
  {:xt/id "https://example.org/~alice/shared.txt"
   ::site/type "Resource"})

(def READ_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/read-user-dir"
   ::site/type "Action"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"})

(def WRITE_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/write-user-dir"
   ::site/type "Action"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/action-args [{}]})

(def READ_SHARED_ACTION
  {:xt/id "https://example.org/actions/read-shared"
   ::site/type "Action"})

(def ALICE_CAN_READ
  {:xt/id "https://example.org/permissions/alice-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}})

(def ALICE_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/alice-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action "https://example.org/actions/write-user-dir"})

(def BOB_CAN_READ
  {:xt/id "https://example.org/permissions/bob-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}})

(def ALICES_SHARES_FILE_WITH_BOB
  {:xt/id "https://example.org/permissions/alice-shares-file-with-bob"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/read-shared"
   ::pass/resource "https://example.org/~alice/shared.txt"})

(def BOB_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/bob-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/write-user-dir"})

(def WRITE_USER_DIR_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/write-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_USER_DIR_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [resource ::site/type "Resource"]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_SHARED_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-shared"]
     [permission ::pass/resource resource]]])

(deftest user-dir-test
  (submit-and-await!
   [
    ;; Actions
    [::xt/put READ_USER_DIR_ACTION]
    [::xt/put READ_SHARED_ACTION]
    [::xt/put WRITE_USER_DIR_ACTION]

    ;; Actors
    [::xt/put ALICE]
    [::xt/put BOB]
    [::xt/put CARLOS]

    ;; Resources
    [::xt/put ALICE_USER_DIR_PRIVATE_FILE]
    [::xt/put ALICE_USER_DIR_SHARED_FILE]

    ;; Permissions
    [::xt/put ALICE_CAN_READ]
    [::xt/put ALICE_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put BOB_CAN_READ]
    [::xt/put BOB_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put ALICES_SHARES_FILE_WITH_BOB]])

  (let [rules (vec (concat WRITE_USER_DIR_RULES READ_USER_DIR_RULES READ_SHARED_RULES))
        db (xt/db *xt-node*)]

    (are [subject actions resource ok?]
        (let [actual (check-permissions db subject actions resource rules)]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can read her own private file.
      "https://example.org/people/alice"
      #{"https://example.org/actions/read-user-dir"}
      "https://example.org/~alice/private.txt"
      true

      ;; Alice can read the file in her user directory which she has shared with
      ;; Bob.
      "https://example.org/people/alice"
      #{"https://example.org/actions/read-user-dir"}
      "https://example.org/~alice/shared.txt"
      true

      ;; Bob cannot read Alice's private file.
      "https://example.org/people/bob"
      #{"https://example.org/actions/read-user-dir"}
      "https://example.org/~alice/private.txt"
      false

      ;; Bob can read the file Alice has shared with him.
      "https://example.org/people/bob"
      #{"https://example.org/actions/read-shared"}
      "https://example.org/~alice/shared.txt"
      true

      ;; Alice can put a file to her user directory
      "https://example.org/people/alice"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~alice/foo.txt"
      true

      ;; Alice can't put a file to Bob's user directory
      "https://example.org/people/alice"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~bob/foo.txt"
      false

      ;; Alice can't put a file outside her user directory
      "https://example.org/people/alice"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/index.html"
      false

      ;; Bob can put a file to his user directory
      "https://example.org/people/bob"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~bob/foo.txt"
      true

      ;; Bob can't put a file to Alice's directory
      "https://example.org/people/bob"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~alice/foo.txt"
      false

      ;; Carl cannot put a file to his user directory, as he hasn't been
      ;; granted the write-user-dir action.
      "https://example.org/people/carl"
      #{"https://example.org/actions/write-user-dir"}
      "https://example.org/~carl/foo.txt"
      false)

    (are [subject actions rules expected]
        (is (= expected (allowed-resources db subject actions rules)))

      ;; Alice can see all her files.
      "https://example.org/people/alice"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{["https://example.org/~alice/shared.txt"]
        ["https://example.org/~alice/private.txt"]}

      ;; Bob can only see the file Alice has shared with him.
      "https://example.org/people/bob"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{["https://example.org/~alice/shared.txt"]})

    ;; Given a resource and a set of actions, which subjects can access
    ;; and via which actions?

    (are [resource actions rules expected]
        (is (= expected (allowed-subjects db resource actions rules)))

      "https://example.org/~alice/shared.txt"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{{:subject "https://example.org/people/bob",
         :action "https://example.org/actions/read-shared"}
        {:subject "https://example.org/people/alice",
         :action "https://example.org/actions/read-user-dir"}}

      "https://example.org/~alice/private.txt"
      #{"https://example.org/actions/read-user-dir"
        "https://example.org/actions/read-shared"}
      (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
      #{{:subject "https://example.org/people/alice",
         :action "https://example.org/actions/read-user-dir"}})))

(deftest constrained-pull-test
  (let [READ_USERNAME_ACTION
         {:xt/id "https://example.org/actions/read-username"
          ::site/type "Action"
          ::pass/pull [::username]}

         READ_SECRETS_ACTION
         {:xt/id "https://example.org/actions/read-secrets"
          ::site/type "Action"
          ::pass/pull [::secret]}

         BOB_CAN_READ_ALICE_USERNAME
         {:xt/id "https://example.org/permissions/bob-can-read-alice-username"
          ::site/type "Permission"
          ::pass/subject "https://example.org/people/bob"
          ::pass/action "https://example.org/actions/read-username"
          ::pass/resource "https://example.org/people/alice"}

         BOB_CAN_READ_ALICE_SECRETS
         {:xt/id "https://example.org/permissions/bob-can-read-alice-secrets"
          ::site/type "Permission"
          ::pass/subject "https://example.org/people/bob"
          ::pass/action "https://example.org/actions/read-secrets"
          ::pass/resource "https://example.org/people/alice"}

         CARLOS_CAN_READ_ALICE_USERNAME
         {:xt/id "https://example.org/permissions/carl-can-read-alice-username"
          ::site/type "Permission"
          ::pass/subject "https://example.org/people/carl"
          ::pass/action "https://example.org/actions/read-username"
          ::pass/resource "https://example.org/people/alice"}

         RULES
         '[[(allowed? permission subject action resource)
            [permission ::pass/subject subject]
            [action :xt/id "https://example.org/actions/read-username"]
            [permission ::pass/resource resource]]

           [(allowed? permission subject action resource)
            [permission ::pass/subject subject]
            [action :xt/id "https://example.org/actions/read-secrets"]
            [permission ::pass/resource resource]]]

         ]

     (submit-and-await!
      [
       ;; Actors
       [::xt/put (assoc ALICE ::secret "foo")]
       [::xt/put BOB]
       [::xt/put CARLOS]

       [::xt/put READ_USERNAME_ACTION]
       [::xt/put READ_SECRETS_ACTION]
       [::xt/put BOB_CAN_READ_ALICE_USERNAME]
       [::xt/put BOB_CAN_READ_ALICE_SECRETS]
       [::xt/put CARLOS_CAN_READ_ALICE_USERNAME]
       ])

     ;; Bob can read Alice's secret
     (let [db (xt/db *xt-node*)]
       (are [subject expected]
           (let [actual (pull-allowed-resource
                         db (:xt/id subject) #{(:xt/id READ_USERNAME_ACTION) (:xt/id READ_SECRETS_ACTION)} (:xt/id ALICE)
                         (vec (concat RULES)))]
             (is (= expected actual)))

         BOB {::username "alice" ::secret "foo"}
         CARLOS {::username "alice"}))))

(deftest pull-allowed-resources-test
  (let [READ_MESSAGE_CONTENT_ACTION
        {:xt/id "https://example.org/actions/read-message-content"
         ::site/type "Action"
         ::pass/pull [::content]}

        READ_MESSAGE_METADATA_ACTION
        {:xt/id "https://example.org/actions/read-message-metadata"
         ::site/type "Action"
         ::pass/pull [::from ::to ::date]}

        ALICE_BELONGS_GROUP_A
        {:xt/id "https://example.org/group/a/alice"
         ::site/type "Permission"
         ::pass/subject (:xt/id ALICE)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}}

        BOB_BELONGS_GROUP_A
        {:xt/id "https://example.org/group/a/bob"
         ::site/type "Permission"
         ::pass/subject (:xt/id BOB)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}}

        ;; Faythe is a trusted admin of Group A. She can see the metadata but
        ;; not the content of messages.
        FAYTHE_MONITORS_GROUP_A
        {:xt/id "https://example.org/group/a/faythe"
         ::site/type "Permission"
         ::pass/subject (:xt/id FAYTHE)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_METADATA_ACTION)}}

        RULES
        '[[(allowed? permission subject action resource)
           [permission ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-message-content"]
           [permission ::group group]
           [resource ::group group]
           [resource ::site/type "Message"]]

          [(allowed? permission subject action resource)
           [permission ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-message-metadata"]
           [permission ::group group]
           [resource ::group group]
           [resource ::site/type "Message"]]]]

    (submit-and-await!
     [
      ;; Actions
      [::xt/put READ_MESSAGE_CONTENT_ACTION]
      [::xt/put READ_MESSAGE_METADATA_ACTION]

      ;; Actors
      [::xt/put ALICE]
      [::xt/put BOB]
      [::xt/put CARLOS]
      [::xt/put FAYTHE]

      ;; Permissions
      [::xt/put ALICE_BELONGS_GROUP_A]
      [::xt/put BOB_BELONGS_GROUP_A]
      [::xt/put FAYTHE_MONITORS_GROUP_A]

      ;; Messages
      [::xt/put
       {:xt/id "https://example.org/messages/1"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id ALICE)
        ::to (:xt/id BOB)
        ::date "2022-03-07T13:00:00"
        ::content "Hello Bob!"}]

      [::xt/put
       {:xt/id "https://example.org/messages/2"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id BOB)
        ::to (:xt/id ALICE)
        ::date "2022-03-07T13:00:10"
        ::content "Hi Alice, how are you?"}]

      [::xt/put
       {:xt/id "https://example.org/messages/3"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id ALICE)
        ::to (:xt/id BOB)
        ::date "2022-03-07T13:00:20"
        ::content "Great thanks. I've reset your password, btw."}]

      [::xt/put
       {:xt/id "https://example.org/messages/4"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id BOB)
        ::to (:xt/id ALICE)
        ::date "2022-03-07T13:00:40"
        ::content "Thanks, what is it?"}]

      [::xt/put
       {:xt/id "https://example.org/messages/5"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id ALICE)
        ::to (:xt/id BOB)
        ::date "2022-03-07T13:00:50"
        ::content "It's 'BananaTree@1230', you should definitely change it at some point."}]

      [::xt/put
       {:xt/id "https://example.org/messages/6"
        ::site/type "Message"
        ::group :a
        ::from (:xt/id BOB)
        ::to (:xt/id ALICE)
        ::date "2022-03-07T13:00:50"
        ::content "Thanks Alice, that's very kind of you - see you at lunch!"}]])

    (let [get-messages
          (fn [subject]
            (pull-allowed-resources
             (xt/db *xt-node*)
             (:xt/id subject)
             #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
               (:xt/id READ_MESSAGE_METADATA_ACTION)}
             RULES))]

      ;; Alice and Bob can read all the messages in the group
      (let [messages (get-messages ALICE)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date ::content} (set (keys (first messages))))))

      (let [messages (get-messages BOB)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date ::content} (set (keys (first messages))))))

      ;; Carlos cannot see any of the messages
      (is (zero? (count (get-messages CARLOS))))

      ;; Faythe can read meta-data of the conversation between Alice and Bob but
      ;; not the content of the messages.
      (let [messages (get-messages FAYTHE)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date} (set (keys (first messages)))))))))

;; Alice has a medical record. She wants to allow Oscar access to it, but only
;; in emergencies (to provide to a doctor in case of urgent need).

;; One way of achieving this is to segment actions by purpose.

(deftest purpose-with-distinct-actions-test
  (let [READ_MEDICAL_RECORD
        {:xt/id "https://example.org/actions/read-medical-record"
         ::site/type "Action"
         ::pass/pull ['*]}

        EMERGENCY_READ_MEDICAL_RECORD
        {:xt/id "https://example.org/actions/emergency-read-medical-record"
         ::site/type "Action"
         ::pass/pull ['*]}

        ALICE_GRANTS_OSCAR_ACCESS
        {:xt/id "https://example.org/alice/medical-record/grants/oscar"
         ::site/type "Permission"
         ::pass/subject (:xt/id OSCAR)
         ::pass/action #{(:xt/id EMERGENCY_READ_MEDICAL_RECORD)}}

        RULES
        '[[(allowed? permission subject action resource)
           [permission ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-medical-record"]
           [resource ::site/type "MedicalRecord"]]

          [(allowed? permission subject action resource)
           [permission ::pass/subject subject]
           [action :xt/id "https://example.org/actions/emergency-read-medical-record"]
           [resource ::site/type "MedicalRecord"]]

          ]]

    (submit-and-await!
     [
      ;; Actions
      [::xt/put READ_MEDICAL_RECORD]
      [::xt/put EMERGENCY_READ_MEDICAL_RECORD]

      ;; Actors
      [::xt/put ALICE]
      [::xt/put OSCAR]

      ;; Permissions
      [::xt/put ALICE_GRANTS_OSCAR_ACCESS]

      ;; Resources
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record"
        ::site/type "MedicalRecord"
        ::content "Medical info"}]])

    (let [get-medical-records
          (fn [subject action]
            (pull-allowed-resources
             (xt/db *xt-node*)
             (:xt/id subject)
             #{(:xt/id action)}
             RULES))

          get-medical-record
          (fn [subject action]
            (pull-allowed-resource
             (xt/db *xt-node*)
             (:xt/id subject)
             #{(:xt/id action)}
             "https://example.org/alice/medical-record"
             RULES))]

      (is (zero? (count (get-medical-records OSCAR READ_MEDICAL_RECORD))))
      (is (= 1 (count (get-medical-records OSCAR EMERGENCY_READ_MEDICAL_RECORD))))
      (is (not (get-medical-record OSCAR READ_MEDICAL_RECORD)))
      (is (get-medical-record OSCAR EMERGENCY_READ_MEDICAL_RECORD)))))

((t/join-fixtures [with-xt])

 (fn []

   ))

;; TODO
;; Next up. Sharing itself. Is Alice even permitted to share her files?
;; read-only, read/write

;; TODO: INTERNAL classification, different security models, see
;; https://en.m.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model

;; TODO: Extend to GraphQL
