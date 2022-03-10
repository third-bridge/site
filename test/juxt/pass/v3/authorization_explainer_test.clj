;; Copyright © 2022, JUXT LTD.

;;(remove-ns 'juxt.pass.v3.authorization-explainer-test)

(ns juxt.pass.v3.authorization-explainer-test
  (:require
   [clojure.test :refer [deftest is are use-fixtures] :as t]
   [juxt.pass.alpha.v3.authorization :as authz]
   [juxt.test.util :refer [with-xt submit-and-await! *xt-node*]]
   [xtdb.api :as xt]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'pass.malli (create-ns 'juxt.pass.alpha.malli))
(alias 'site (create-ns 'juxt.site.alpha))

(use-fixtures :each with-xt)

;; Note: if you're not familiar with the Alice and Bob characters, see
;; https://en.wikipedia.org/wiki/Alice_and_Bob#Cast_of_characters

(def ALICE
  {:xt/id "https://example.org/people/alice"
   ::site/type "User"
   ::username "alice"})

(def BOB
  {:xt/id "https://example.org/people/bob"
   ::site/type "User"
   ::username "bob"})

(def CARLOS
  {:xt/id "https://example.org/people/carl"
   ::site/type "User"
   ::username "carl"})

(def FAYTHE
  {:xt/id "https://example.org/people/faythe"
   ::site/type "User"
   ::username "faythe"})

(def OSCAR
  {:xt/id "https://example.org/people/oscar"
   ::site/type "User"
   ::username "oscar"})

;; Applications

(def USER_APP
  {:xt/id "https://example.org/_site/apps/user"
   ::name "User App"
   ::pass/client-id "100"
   ::pass/client-secret "SecretUmbrella"})

;; All access is via an access token. Access tokens are created for individual
;; subjects using a specific application.

(def ALICE_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/alice"
   ::pass/subject (:xt/id ALICE)
   ::pass/application-client (:xt/id USER_APP)})

(def BOB_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/bob"
   ::pass/subject (:xt/id BOB)
   ::pass/application-client (:xt/id USER_APP)})

(def CARLOS_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/carlos"
   ::pass/subject (:xt/id CARLOS)
   ::pass/application-client (:xt/id USER_APP)})

(def FAYTHE_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/faythe"
   ::pass/subject (:xt/id FAYTHE)
   ::pass/application-client (:xt/id USER_APP)})

(def OSCAR_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/oscar"
   ::pass/subject (:xt/id OSCAR)
   ::pass/application-client (:xt/id USER_APP)})

;; TODO: INTERNAL classification, different security models, see
;; https://en.m.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model
;; PUBLIC

;; User directories

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/actions/resources.

;; TODO: Not a great first example! Try something easier to start with.

(def ALICE_USER_DIR_PRIVATE_FILE
  {:xt/id "https://example.org/~alice/private.txt"})

(def ALICE_USER_DIR_SHARED_FILE
  {:xt/id "https://example.org/~alice/shared.txt"})

(def READ_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/read-user-dir"
   ::site/type "Action"
   ::pass/scope "read:resource"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"})

(def WRITE_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/write-user-dir"
   ::site/type "Action"
   ::pass/scope "write:resource"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/action-args [{}]})

(def READ_SHARED_ACTION
  {:xt/id "https://example.org/actions/read-shared"
   ::site/type "Action"
   ::pass/scope "read:resource"})

(def ALICE_CAN_READ
  {:xt/id "https://example.org/permissions/alice-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}
   ::pass/purpose nil})

(def ALICE_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/alice-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action "https://example.org/actions/write-user-dir"
   ::pass/purpose nil})

(def BOB_CAN_READ
  {:xt/id "https://example.org/permissions/bob-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}
   ::pass/purpose nil})

(def ALICES_SHARES_FILE_WITH_BOB
  {:xt/id "https://example.org/permissions/alice-shares-file-with-bob"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/read-shared"
   ::pass/purpose nil
   ::pass/resource "https://example.org/~alice/shared.txt"})

(def BOB_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/bob-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/write-user-dir"
   ::pass/purpose nil})

(def WRITE_USER_DIR_RULES
  '[[(allowed? permission access-token action resource)
     [access-token ::pass/subject subject]
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/write-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_USER_DIR_RULES
  '[[(allowed? permission access-token action resource)
     [access-token ::pass/subject subject]
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [resource :xt/id]
     [subject ::username username]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_SHARED_RULES
  '[[(allowed? permission access-token action resource)
     [access-token ::pass/subject subject]
     [permission ::pass/subject subject]
     [resource :xt/id]
     [action :xt/id "https://example.org/actions/read-shared"]
     [permission ::pass/resource resource]]])

;; Scopes. Actions inhabit scopes.

(deftest user-dir-test
  (submit-and-await!
   [
    ;; Subjects
    [::xt/put ALICE]
    [::xt/put BOB]
    [::xt/put CARLOS]

    ;; Access tokens
    [::xt/put ALICE_ACCESS_TOKEN]
    [::xt/put BOB_ACCESS_TOKEN]
    [::xt/put CARLOS_ACCESS_TOKEN]

    ;; Actions
    [::xt/put READ_USER_DIR_ACTION]
    [::xt/put READ_SHARED_ACTION]
    [::xt/put WRITE_USER_DIR_ACTION]

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

    (are [access-token scope actions resource ok?]
        (let [actual (authz/check-permissions
                      db {:access-token access-token
                          :scope scope
                          :actions actions
                          :resource resource
                          :rules rules})]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can read her own private file.
        "https://example.org/tokens/alice"
        #{"read:resource"}
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/private.txt"
        true

        ;; But not unless the scope allows
        "https://example.org/tokens/alice"
        #{}
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/private.txt"
        false

        ;; Alice can read the file in her user directory which she has shared with
        ;; Bob.
        "https://example.org/tokens/alice"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/shared.txt"
        true

        ;; Bob cannot read Alice's private file.
        "https://example.org/tokens/bob"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/read-user-dir"}
        "https://example.org/~alice/private.txt"
        false

        ;; Bob can read the file Alice has shared with him.
        "https://example.org/tokens/bob"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/read-shared"}
        "https://example.org/~alice/shared.txt"
        true

        ;; Alice can put a file to her user directory
        "https://example.org/tokens/alice"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~alice/foo.txt"
        true

        ;; Alice can't put a file to Bob's user directory
        "https://example.org/tokens/alice"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~bob/foo.txt"
        false

        ;; Alice can't put a file outside her user directory
        "https://example.org/tokens/alice"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/index.html"
        false

        ;; Bob can put a file to his user directory
        "https://example.org/tokens/bob"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~bob/foo.txt"
        true

        ;; Bob can't put a file to Alice's directory
        "https://example.org/tokens/bob"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~alice/foo.txt"
        false

        ;; Carl cannot put a file to his user directory, as he hasn't been
        ;; granted the write-user-dir action.
        "https://example.org/tokens/carl"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/write-user-dir"}
        "https://example.org/~carl/foo.txt"
        false
        )

    (are [access-token scope actions rules expected]
        (is (= expected
               (authz/allowed-resources
                db
                {:access-token access-token
                 :scope scope
                 :actions actions
                 :rules rules})))

      ;; Alice can see all her files.
        "https://example.org/tokens/alice"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
        #{["https://example.org/~alice/shared.txt"]
          ["https://example.org/~alice/private.txt"]}

        ;; Bob can only see the file Alice has shared with him.
        "https://example.org/tokens/bob"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
        #{["https://example.org/~alice/shared.txt"]}

        ;; Carl sees nothing
        "https://example.org/tokens/carl"
        #{"read:resource" "write:resource"}
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
        #{})

    ;; Given a resource and a set of actions, which subjects can access
    ;; and via which actions?

    (are [resource actions scope rules expected]
        (is (= expected (authz/allowed-subjects
                         db
                         {:resource resource
                          :actions actions
                          :scope scope
                          :rules rules})))

        "https://example.org/~alice/shared.txt"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{"read:resource"}
        (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
        #{{:subject "https://example.org/people/bob",
           :action "https://example.org/actions/read-shared"}
          {:subject "https://example.org/people/alice",
           :action "https://example.org/actions/read-user-dir"}}

        "https://example.org/~alice/private.txt"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{"read:resource"}
        (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
        #{{:subject "https://example.org/people/alice",
           :action "https://example.org/actions/read-user-dir"}}

        ;; Cannot see anything without a scope
        "https://example.org/~alice/shared.txt"
        #{"https://example.org/actions/read-user-dir"
          "https://example.org/actions/read-shared"}
        #{}
        (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES))
        #{})))

(deftest constrained-pull-test
  (let [READ_USERNAME_ACTION
        {:xt/id "https://example.org/actions/read-username"
         ::site/type "Action"
         ::pass/scope "read"
         ::pass/pull [::username]}

        READ_SECRETS_ACTION
        {:xt/id "https://example.org/actions/read-secrets"
         ::site/type "Action"
         ::pass/scope "read"
         ::pass/pull [::secret]}

        BOB_CAN_READ_ALICE_USERNAME
        {:xt/id "https://example.org/permissions/bob-can-read-alice-username"
         ::site/type "Permission"
         ::pass/subject "https://example.org/people/bob"
         ::pass/action "https://example.org/actions/read-username"
         ::pass/purpose nil
         ::pass/resource "https://example.org/people/alice"}

        BOB_CAN_READ_ALICE_SECRETS
        {:xt/id "https://example.org/permissions/bob-can-read-alice-secrets"
         ::site/type "Permission"
         ::pass/subject "https://example.org/people/bob"
         ::pass/action "https://example.org/actions/read-secrets"
         ::pass/purpose nil
         ::pass/resource "https://example.org/people/alice"}

        CARLOS_CAN_READ_ALICE_USERNAME
        {:xt/id "https://example.org/permissions/carl-can-read-alice-username"
         ::site/type "Permission"
         ::pass/subject "https://example.org/people/carl"
         ::pass/action "https://example.org/actions/read-username"
         ::pass/purpose nil
         ::pass/resource "https://example.org/people/alice"}

        rules
        '[[(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-username"]
           [permission ::pass/resource resource]]

          [(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-secrets"]
           [permission ::pass/resource resource]]]]

    (submit-and-await!
     [
      ;; Actors
      [::xt/put (assoc ALICE ::secret "foo")]
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put BOB]
      [::xt/put BOB_ACCESS_TOKEN]
      [::xt/put CARLOS]
      [::xt/put CARLOS_ACCESS_TOKEN]

      [::xt/put READ_USERNAME_ACTION]
      [::xt/put READ_SECRETS_ACTION]
      [::xt/put BOB_CAN_READ_ALICE_USERNAME]
      [::xt/put BOB_CAN_READ_ALICE_SECRETS]
      [::xt/put CARLOS_CAN_READ_ALICE_USERNAME]
      ])

    ;; Bob can read Alice's secret
    (let [db (xt/db *xt-node*)]
      (are [access-token expected]
          (let [actual
                (authz/pull-allowed-resource
                 db
                 {:access-token (:xt/id access-token)
                  :scope #{"read"}
                  :actions #{(:xt/id READ_USERNAME_ACTION) (:xt/id READ_SECRETS_ACTION)}
                  :resource (:xt/id ALICE)
                  :rules rules})]
            (is (= expected actual)))

        BOB_ACCESS_TOKEN {::username "alice" ::secret "foo"}
        CARLOS_ACCESS_TOKEN {::username "alice"}))))

(deftest pull-allowed-resources-test
  (let [READ_MESSAGE_CONTENT_ACTION
        {:xt/id "https://example.org/actions/read-message-content"
         ::site/type "Action"
         ::pass/scope "read:messages"
         ::pass/pull [::content]}

        READ_MESSAGE_METADATA_ACTION
        {:xt/id "https://example.org/actions/read-message-metadata"
         ::site/type "Action"
         ::pass/scope "read:messages"
         ::pass/pull [::from ::to ::date]}

        ALICE_BELONGS_GROUP_A
        {:xt/id "https://example.org/group/a/alice"
         ::site/type "Permission"
         ::pass/subject (:xt/id ALICE)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}
         ::pass/purpose nil}

        BOB_BELONGS_GROUP_A
        {:xt/id "https://example.org/group/a/bob"
         ::site/type "Permission"
         ::pass/subject (:xt/id BOB)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}
         ::pass/purpose nil}

        ;; Faythe is a trusted admin of Group A. She can see the metadata but
        ;; not the content of messages.
        FAYTHE_MONITORS_GROUP_A
        {:xt/id "https://example.org/group/a/faythe"
         ::site/type "Permission"
         ::pass/subject (:xt/id FAYTHE)
         ::group :a
         ::pass/action #{(:xt/id READ_MESSAGE_METADATA_ACTION)}
         ::pass/purpose nil}

        rules
        '[[(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-message-content"]
           [permission ::group group]
           [resource ::group group]
           [resource ::site/type "Message"]]

          [(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
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
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put BOB]
      [::xt/put BOB_ACCESS_TOKEN]
      [::xt/put CARLOS]
      [::xt/put CARLOS_ACCESS_TOKEN]
      [::xt/put FAYTHE]
      [::xt/put FAYTHE_ACCESS_TOKEN]

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
          (fn [access-token]
            (authz/pull-allowed-resources
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:messages"}
              :actions #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                         (:xt/id READ_MESSAGE_METADATA_ACTION)}
              :rules rules}))]

      ;; Alice and Bob can read all the messages in the group
      (let [messages (get-messages ALICE_ACCESS_TOKEN)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date ::content} (set (keys (first messages))))))

      (let [messages (get-messages BOB_ACCESS_TOKEN)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date ::content} (set (keys (first messages))))))

      ;; Carlos cannot see any of the messages
      (is (zero? (count (get-messages CARLOS_ACCESS_TOKEN))))

      ;; Faythe can read meta-data of the conversation between Alice and Bob but
      ;; not the content of the messages.
      (let [messages (get-messages FAYTHE_ACCESS_TOKEN)]
        (is (= 6 (count messages)))
        (is (= #{::from ::to ::date} (set (keys (first messages))))))

      ;; We can specify an :include-rules entry to pull-allowed-resources to
      ;; restrict the resources that are found to some additional
      ;; criteria. Currently this is as close as we get to providing full query
      ;; capabilities.
      (is (= 3 (count
                (authz/pull-allowed-resources
                 (xt/db *xt-node*)
                 {:access-token (:xt/id ALICE_ACCESS_TOKEN)
                  :scope #{"read:messages"}
                  :actions #{(:xt/id READ_MESSAGE_CONTENT_ACTION)
                             (:xt/id READ_MESSAGE_METADATA_ACTION)}
                  :rules rules
                  :include-rules [['(include? access-token action message)
                                   ['message ::from (:xt/id ALICE)]]]})))))))

;; Alice has a medical record. She wants to allow Oscar access to it, but only
;; in emergencies (to provide to a doctor in case of urgent need).

;; One way of achieving this is to segment actions by purpose.

(deftest purpose-with-distinct-actions-test
  (let [READ_MEDICAL_RECORD_ACTION
        {:xt/id "https://example.org/actions/read-medical-record"
         ::site/type "Action"
         ::pass/scope "read:health"
         ::pass/pull ['*]
         ::pass/alert-log false}

        EMERGENCY_READ_MEDICAL_RECORD_ACTION
        {:xt/id "https://example.org/actions/emergency-read-medical-record"
         ::site/type "Action"
         ::pass/scope "read:health"
         ::pass/pull ['*]
         ::pass/alert-log true}

        rules
        '[[(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
           [action :xt/id "https://example.org/actions/read-medical-record"]
           [resource ::site/type "MedicalRecord"]]

          [(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
           [action :xt/id "https://example.org/actions/emergency-read-medical-record"]
           [resource ::site/type "MedicalRecord"]]]]

    (submit-and-await!
     [
      ;; Subject
      [::xt/put ALICE]
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put OSCAR]
      [::xt/put OSCAR_ACCESS_TOKEN]

      ;; Actions
      [::xt/put READ_MEDICAL_RECORD_ACTION]
      [::xt/put EMERGENCY_READ_MEDICAL_RECORD_ACTION]

      ;; Permissions
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record/grants/oscar"
        ::site/type "Permission"
        ::pass/subject (:xt/id OSCAR)
        ::pass/action #{(:xt/id EMERGENCY_READ_MEDICAL_RECORD_ACTION)}
        ::pass/purpose nil}]

      ;; Resources
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record"
        ::site/type "MedicalRecord"
        ::content "Medical info"}]])

    (let [get-medical-records
          (fn [access-token action]
            (authz/pull-allowed-resources
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :rules rules}))

          get-medical-record
          (fn [access-token action]
            (authz/pull-allowed-resource
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :resource "https://example.org/alice/medical-record"
              :rules rules}))]

      (is (zero? (count (get-medical-records OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION))))
      (is (= 1 (count (get-medical-records OSCAR_ACCESS_TOKEN EMERGENCY_READ_MEDICAL_RECORD_ACTION))))
      (is (not (get-medical-record OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION)))
      (is (get-medical-record OSCAR_ACCESS_TOKEN EMERGENCY_READ_MEDICAL_RECORD_ACTION)))))

;; An alternative way of achieving the same result is to specify a purpose when
;; granting a permission.

(deftest purpose-test
  (let [READ_MEDICAL_RECORD_ACTION
        {:xt/id "https://example.org/actions/read-medical-record"
         ::site/type "Action"
         ::pass/scope "read:health"
         ::pass/pull ['*]}

        rules
        '[[(allowed? permission access-token action resource)
           [permission ::pass/subject subject]
           [access-token ::pass/subject subject]
           [permission ::pass/purpose purpose]
           [action :xt/id "https://example.org/actions/read-medical-record"]
           [resource ::site/type "MedicalRecord"]]]]

    (submit-and-await!
     [
      ;; Actions
      [::xt/put READ_MEDICAL_RECORD_ACTION]

      ;; Actors
      [::xt/put ALICE]
      [::xt/put ALICE_ACCESS_TOKEN]
      [::xt/put OSCAR]
      [::xt/put OSCAR_ACCESS_TOKEN]

      ;; Purposes
      [::xt/put
       {:xt/id "https://example.org/purposes/emergency"
        ::site/type "Purpose"
        ::description "Emergency access to vital personal information."
        ::gdpr-interest "VITAL"}]

      ;; Permissions
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record/grants/oscar"
        ::site/type "Permission"
        ::pass/subject (:xt/id OSCAR)
        ::pass/action (:xt/id READ_MEDICAL_RECORD_ACTION)
        ::pass/purpose "https://example.org/purposes/emergency"}]

      ;; Resources
      [::xt/put
       {:xt/id "https://example.org/alice/medical-record"
        ::site/type "MedicalRecord"
        ::content "Medical info"}]])

    (let [get-medical-records
          (fn [access-token action purpose]
            (authz/pull-allowed-resources
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :purpose purpose
              :rules rules}))

          get-medical-record
          (fn [access-token action purpose]
            (authz/pull-allowed-resource
             (xt/db *xt-node*)
             {:access-token (:xt/id access-token)
              :scope #{"read:health"}
              :actions #{(:xt/id action)}
              :purpose purpose
              :resource "https://example.org/alice/medical-record"
              :rules rules}))]

      (is (zero? (count (get-medical-records OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/marketing"))))
      (is (= 1 (count (get-medical-records OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/emergency"))))

      (is (nil? (get-medical-record OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/marketing")))
      (is (get-medical-record OSCAR_ACCESS_TOKEN READ_MEDICAL_RECORD_ACTION "https://example.org/purposes/emergency")))))

;; Bootstrapping

;; TODO
;; Next up. Sharing itself. Is Alice even permitted to share her files?
;; read-only, read/write
;; Answer @jms's question: is it possible for Sue to grant a resource for
;; which she hasn't herself access?

(def SUE
  {:xt/id "https://example.org/people/sue"
   ::site/type "Person"
   ::username "sue"})

(def ADMIN_APP
  {:xt/id "https://example.org/_site/apps/admin"
   ::name "Admin App"
   ::pass/client-id "101"
   ::pass/client-secret "SecretArmadillo"})

(def SUE_ACCESS_TOKEN
  {:xt/id "https://example.org/tokens/sue"
   ::pass/subject (:xt/id SUE)
   ::pass/application-client (:xt/id ADMIN_APP)})

(def CREATE_PERSON
  {:xt/id "https://example.org/actions/create-person"
   ::site/type "Action"
   ::pass/scope "write:admin"
   ::pass/action-args
   [{::pass.malli/schema
     [:map
      [::site/type [:= "Person"]]
      [::username [:string]]]

     ::pass/process
     [
      ;; Though we could use a Malli value transformer here, at this stage is
      ;; doesn't feel beneficial to lean too heavily on Malli's extensive
      ;; feature set.
      [::pass/merge {::site/type "Person"}]
      [::pass.malli/validate]]}]})

(def CREATE_IDENTITY
  {:xt/id "https://example.org/actions/create-identity"
   ::site/type "Action"
   ::pass/scope "write:admin"
   ::pass/action-args [{}]})

(deftest call-action-test
  (let [rules ['[(allowed? permission access-token action resource)
                 [permission ::pass/subject subject]
                 [access-token ::pass/subject subject]]]]
    (submit-and-await!
     [
      ;; People
      [::xt/put SUE]
      [::xt/put SUE_ACCESS_TOKEN]

      [::xt/put CARLOS]
      [::xt/put CARLOS_ACCESS_TOKEN]

      ;; Actions
      [::xt/put CREATE_PERSON]
      [::xt/put CREATE_IDENTITY]

      ;; Permissions
      [::xt/put
       {:xt/id "https://example.org/permissions/sue/create-person"
        ::site/type "Permission"
        ::pass/subject (:xt/id SUE)
        ::pass/action (:xt/id CREATE_PERSON)
        ::pass/purpose nil #_"https://example.org/purposes/bootsrapping-system"}]

      ;; Functions
      (authz/register-call-action-fn)])

    ;; Sue creates the user Alice, with an identity
    (is
     (seq
      (authz/check-permissions
       (xt/db *xt-node*)
       {:access-token (:xt/id SUE_ACCESS_TOKEN)
        :scope #{"write:admin"}
        :actions #{(:xt/id CREATE_PERSON)}
        :rules rules})))

    (authz/submit-call-action-sync
     *xt-node*
     {:access-token (:xt/id SUE_ACCESS_TOKEN)
      :scope #{"write:admin"}
      :action (:xt/id CREATE_PERSON)
      :rules rules
      :args [{:xt/id ALICE ::username "alice"}]})

    (is (xt/entity (xt/db *xt-node*) ALICE))

    ;; This fails because we haven't provided the ::username
    (is
     (thrown?
      AssertionError
      (authz/submit-call-action-sync
       *xt-node*
       {:access-token (:xt/id SUE_ACCESS_TOKEN)
        :scope #{"write:admin"}
        :action (:xt/id CREATE_PERSON)
        :rules rules
        :args [{:xt/id ALICE}]})))))

#_((t/join-fixtures [with-xt])
   (fn []
     :ok
     ))

;; TODO: Extend to GraphQL
;;
;; TODO: Subject access from 'inside' versus 'outside' the perimeter
;;
;; TODO: Continue bootstrapping so Alice can do stuff
;;
;; TODO: Create action list-persons which can be in the scope read:internal ?
;; Or can list-persons as an action be granted to INTERNAL?
;; Does list-persons refer to a resource? I suppose so, it's read:resource on /people/

;; Create a list-persons action
;; Create /people/ resource
;; Grant list-persons on /people/ to Alice
;; Can a GET from Alice to /people/ trigger a list-persons actions?
;; Can a list-persons action be configured to do a a query?
